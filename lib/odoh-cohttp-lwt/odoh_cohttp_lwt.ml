(* Oblivious DoH over cohttp-lwt. *)

open Lwt.Syntax
module Body = Cohttp_lwt.Body
module Service = Odoh.Service

type handler = Http.Request.t -> Body.t -> (Http.Response.t * Body.t) Lwt.t
type resolve = string -> string Lwt.t

let fields headers =
  List.map
    (fun (k, v) -> (String.lowercase_ascii k, v))
    (Http.Header.to_list headers)

let respond (response : Service.response) =
  let body = response.body in
  Lwt.return
    ( Http.Response.make
        ~status:(Http.Status.of_int response.status)
        ~headers:
          (Http.Header.add_unless_exists
             (Http.Header.of_list response.headers)
             "content-length"
             (string_of_int (String.length body)))
        (),
      Body.of_string body )

(* The content of a body, unless it is longer than [max_size]: then the rest is
   read without being kept, since a connection is only free again once its body
   has been read. *)
let read ~max_size headers body =
  let too_long () =
    let+ () = Body.drain_body body in
    None
  in
  if Service.exceeds ~max_size (fields headers) then too_long ()
  else
    let buffer = Buffer.create 1024 in
    let stream = Body.to_stream body in
    let rec loop () =
      let* chunk = Lwt_stream.get stream in
      match chunk with
      | None -> Lwt.return_some (Buffer.contents buffer)
      | Some chunk when Buffer.length buffer + String.length chunk > max_size ->
          too_long ()
      | Some chunk ->
          Buffer.add_string buffer chunk;
          loop ()
    in
    loop ()

(* [f ()], if the admission lets it in, and [busy] otherwise. *)
let admitted admission f =
  if Service.Admission.admit admission then
    Lwt.finalize f (fun () -> Lwt.return (Service.Admission.release admission))
  else respond Service.busy

let request_path (request : Http.Request.t) =
  Uri.path (Uri.of_string request.resource)

let meth (request : Http.Request.t) = Http.Method.to_string request.meth

module Target = struct
  let configs service _request body =
    let* () = Body.drain_body body in
    respond (Service.Target.configs service)

  let queries service resolve (request : Http.Request.t) body =
    admitted (Service.Target.admission service) @@ fun () ->
    let* content =
      read
        ~max_size:(Service.Target.max_message_size service)
        request.headers body
    in
    match content with
    | None -> respond Service.content_too_large
    | Some content -> (
        match
          Service.Target.receive service ~meth:(meth request)
            ~headers:(fields request.headers) content
        with
        | Respond response -> respond response
        | Resolve (query, seal) ->
            let* answer =
              Lwt.catch
                (fun () -> resolve query)
                (fun _ -> Lwt.return (Service.servfail query))
            in
            respond (seal answer))

  let handler ?(path = "/dns-query") service resolve (request : Http.Request.t)
      body =
    let requested = request_path request in
    if request.meth = `GET && requested = Service.well_known_configs_path then
      configs service request body
    else if requested = path then queries service resolve request body
    else
      let* () = Body.drain_body body in
      respond Service.not_found
end

module Make (Http_client : Cohttp_lwt.S.Client) = struct
  (* A response, and its content unless it is longer than [max_size]. *)
  let fetch ~max_size call =
    let* (response : Http.Response.t), body = call () in
    let+ content = read ~max_size response.headers body in
    (response, content)

  let post ?ctx ~max_size ~uri headers content =
    fetch ~max_size (fun () ->
        Http_client.post ?ctx
          ~headers:(Http.Header.of_list headers)
          ~body:(Body.of_string content) uri)

  module Client = struct
    let too_large max_size = Error (Odoh.Error.Content_too_large max_size)

    let configs ?ctx ?(max_response_size = Service.default_max_message_size) uri
        =
      let+ response, content =
        fetch ~max_size:max_response_size (fun () -> Http_client.get ?ctx uri)
      in
      match content with
      | None -> too_large max_response_size
      | Some content ->
          Service.Client.configs
            ~status:(Http.Status.to_int response.status)
            ~headers:(fields response.headers) content

    let query ?ctx ?(max_response_size = Service.default_max_message_size) ~rng
        ?padding ~proxy config dns_query =
      match Service.Client.start ~rng ?padding config dns_query with
      | Error _ as e -> Lwt.return e
      | Ok (request, exchange) -> (
          let+ response, content =
            post ?ctx ~max_size:max_response_size ~uri:proxy request.headers
              request.body
          in
          match content with
          | None -> too_large max_response_size
          | Some content ->
              Service.Client.finish exchange
                ~status:(Http.Status.to_int response.status)
                ~headers:(fields response.headers) content)
  end

  module Proxy = struct
    let handler ?ctx proxy (request : Http.Request.t) body =
      admitted (Service.Proxy.admission proxy) @@ fun () ->
      let max_size = Service.Proxy.max_message_size proxy in
      let* content = read ~max_size request.headers body in
      match content with
      | None -> respond Service.content_too_large
      | Some content -> (
          match
            Service.Proxy.request proxy ~meth:(meth request)
              ~headers:(fields request.headers) ~target:request.resource content
          with
          | Error response -> respond response
          | Ok (uri, forwarded) ->
              let* answer =
                Lwt.catch
                  (fun () ->
                    let+ (response : Http.Response.t), content =
                      post ?ctx ~max_size ~uri:(Uri.of_string uri)
                        forwarded.headers forwarded.body
                    in
                    match content with
                    | None ->
                        Service.Proxy.unreachable proxy
                          ~error:"http_response_body_size" ()
                    | Some content ->
                        Service.Proxy.response proxy
                          ~status:(Http.Status.to_int response.status)
                          ~headers:(fields response.headers) content)
                  (fun _ -> Lwt.return (Service.Proxy.unreachable proxy ()))
              in
              respond answer)
  end

  module Resolver = struct
    let dns_message = "application/dns-message"

    let doh ?ctx ?(max_response_size = 65535) uri query =
      Lwt.catch
        (fun () ->
          let+ response, content =
            post ?ctx ~max_size:max_response_size ~uri
              [ ("content-type", dns_message); ("accept", dns_message) ]
              query
          in
          let content_type =
            Option.value ~default:""
              (Http.Header.get response.headers "content-type")
          in
          match content with
          | Some answer
            when Http.Status.to_int response.status = 200
                 && Odoh.Media_type.matches dns_message content_type
                 && answer <> "" ->
              answer
          | _ -> Service.servfail query)
        (fun _ -> Lwt.return (Service.servfail query))
  end
end
