(* The client, proxy, and target of RFC 9230 Section 4, without I/O. *)

type request = { headers : (string * string) list; body : string }

type response = Http_binding.error_response = {
  status : int;
  headers : (string * string) list;
  body : string;
}

let ( let* ) = Result.bind
let well_known_configs_path = "/.well-known/odohconfigs"
let default_max_message_size = Http_binding.max_message_length
let default_max_in_flight = 256

let exceeds ~max_size headers =
  match Http_binding.header headers "content-length" with
  | None -> false
  | Some n -> (
      match int_of_string_opt (String.trim n) with
      | Some n -> n > max_size
      (* A length that does not parse is refused too. *)
      | None -> true)

let plain status headers =
  { status; headers = ("cache-control", "no-store") :: headers; body = "" }

let content_too_large = plain 413 []
let busy = plain 503 [ ("retry-after", "1") ]
let not_found = plain 404 []

let positive name n =
  if n <= 0 then invalid_arg (Printf.sprintf "Odoh.Service: %s" name)

module Admission = struct
  type t = { in_flight : int Atomic.t; max_in_flight : int }

  let create ~max_in_flight =
    positive "max_in_flight" max_in_flight;
    { in_flight = Atomic.make 0; max_in_flight }

  let rec admit t =
    let n = Atomic.get t.in_flight in
    if n >= t.max_in_flight then false
    else if Atomic.compare_and_set t.in_flight n (n + 1) then true
    else admit t

  let release t = Atomic.decr t.in_flight
end

module Client = struct
  let configs ~status ~headers:_ body =
    if status < 200 || status > 299 then Error (Error.Unexpected_status status)
    else Config.decode_list body

  type exchange = Client.context

  let start ~rng ?padding config dns_query =
    let* body, context = Client.encrypt_query ~rng ?padding config dns_query in
    Ok ({ headers = Http_binding.Client.request_headers; body }, context)

  let finish context ~status ~headers body =
    let* () = Http_binding.Client.check_response ~status ~headers in
    Client.decrypt_response context body
end

module Proxy = struct
  type route = Proxy.target -> string option

  let allow ?(ports = [ 443 ]) hosts =
    let hosts = List.map String.lowercase_ascii hosts in
    fun (target : Proxy.target) ->
      let port_ok =
        match target.port with None -> true | Some p -> List.mem p ports
      in
      if port_ok && List.mem target.host hosts then
        Some (Proxy.target_uri target)
      else None

  type t = {
    name : string;
    template : Proxy.Template.t;
    route : route;
    max_message_size : int;
    admission : Admission.t;
  }

  let create ?(name = "odoh-proxy")
      ?(max_message_size = default_max_message_size)
      ?(max_in_flight = default_max_in_flight) ~template ~route () =
    positive "max_message_size" max_message_size;
    {
      name;
      template;
      route;
      max_message_size;
      admission = Admission.create ~max_in_flight;
    }

  let name t = t.name
  let max_message_size t = t.max_message_size
  let admission t = t.admission

  let request t ~meth ~headers ~target body =
    let refuse e = Error (Proxy.error_response ~name:t.name e) in
    match Proxy.check_request ~meth ~headers with
    | Error e -> refuse e
    | Ok () -> (
        if String.length body > t.max_message_size then Error content_too_large
        else
          match Proxy.target_of_request t.template target with
          | Error e -> refuse e
          | Ok target -> (
              match t.route target with
              | None ->
                  Error
                    (Proxy.denied ~name:t.name ~details:"target not allowed" ())
              | Some uri ->
                  Ok (uri, { headers = Proxy.target_request_headers; body })))

  let response t ~status ~headers body =
    if String.length body > t.max_message_size then
      Proxy.unreachable ~name:t.name ~error:"http_response_body_size" ()
    else
      {
        status;
        headers = Proxy.response_headers ~name:t.name ~status ~headers;
        body;
      }

  let unreachable t ?(error = "destination_unavailable") () =
    Proxy.unreachable ~name:t.name ~error ()
end

let servfail query =
  let n = String.length query in
  let b = Buffer.create 64 in
  if n < 12 then Buffer.add_string b "\x00\x00\x80\x82"
  else (
    Buffer.add_string b (String.sub query 0 2);
    (* QR, the opcode and RD of the query, then RA and RCODE 2. *)
    Buffer.add_uint8 b (Char.code query.[2] land 0x79 lor 0x80);
    Buffer.add_uint8 b 0x82);
  let question =
    if n < 12 || String.get_uint16_be query 4 <> 1 then None
    else
      (* The name is a sequence of labels, without compression in a query. *)
      let rec name i =
        if i >= n then None
        else
          let len = Char.code query.[i] in
          if len = 0 then Some (i + 1)
          else if len land 0xc0 <> 0 then None
          else name (i + 1 + len)
      in
      match name 12 with
      | Some e when e + 4 <= n -> Some (String.sub query 12 (e + 4 - 12))
      | _ -> None
  in
  Buffer.add_uint16_be b (if question = None then 0 else 1);
  Buffer.add_string b "\x00\x00\x00\x00\x00\x00";
  Option.iter (Buffer.add_string b) question;
  Buffer.contents b

module Target = struct
  type t = {
    rng : Mirage_crypto_rng.g;
    padding : Message.Padding.t option;
    target : Target.t;
    max_message_size : int;
    admission : Admission.t;
  }

  let create ~rng ?padding ?(max_message_size = default_max_message_size)
      ?(max_in_flight = default_max_in_flight) target =
    positive "max_message_size" max_message_size;
    {
      rng;
      padding;
      target;
      max_message_size;
      admission = Admission.create ~max_in_flight;
    }

  let max_message_size t = t.max_message_size
  let admission t = t.admission

  let configs t =
    {
      status = 200;
      headers =
        [
          ("content-type", "application/octet-stream");
          ("cache-control", "max-age=3600");
        ];
      body = Target.encoded_configs t.target;
    }

  type step = Respond of response | Resolve of string * (string -> response)

  let clear e = Respond (Http_binding.Target.error_response e)

  let seal t context query dns_response =
    let encrypt dns =
      Target.encrypt_response ~rng:t.rng ?padding:t.padding context dns
    in
    (* A DNS response too long to encrypt is answered with a SERVFAIL. *)
    match
      match encrypt dns_response with
      | Ok _ as ok -> ok
      | Error (Error.Invalid_dns_message _) -> encrypt (servfail query)
      | Error _ as e -> e
    with
    | Ok body ->
        { status = 200; headers = Http_binding.Target.response_headers; body }
    | Error e -> Http_binding.Target.error_response e

  let receive t ~meth ~headers body =
    match Http_binding.Target.check_request ~meth ~headers with
    | Error e -> clear e
    | Ok () -> (
        if String.length body > t.max_message_size then
          Respond content_too_large
        else
          match Target.decrypt_query t.target body with
          | Error e -> clear e
          | Ok (query, context) -> Resolve (query, seal t context query))
end
