(* A client, a proxy, a target, and a DoH resolver over cohttp-lwt-unix, on this
   machine. *)

open Lwt.Syntax
module O = Odoh_cohttp_lwt
module C = O.Make (Cohttp_lwt_unix.Client)
module Server = Cohttp_lwt_unix.Server
module Body = Cohttp_lwt.Body

let () = Mirage_crypto_rng_unix.use_default ()
let rng = Mirage_crypto_rng.default_generator ()

let unhex h =
  String.init
    (String.length h / 2)
    (fun i -> Char.chr (int_of_string ("0x" ^ String.sub h (2 * i) 2)))

let dns_query =
  unhex "abcd01000001000000000000076578616d706c6503636f6d0000010001"

let dns_response =
  unhex
    "abcd81800001000100000000076578616d706c6503636f6d0000010001c00c000100010000012c00045db8d722"

let free_port () =
  let socket = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.bind socket (Unix.ADDR_INET (Unix.inet_addr_loopback, 0));
  let port =
    match Unix.getsockname socket with
    | Unix.ADDR_INET (_, port) -> port
    | Unix.ADDR_UNIX _ -> assert false
  in
  Unix.close socket;
  port

let local port path =
  Uri.of_string (Printf.sprintf "http://127.0.0.1:%d%s" port path)

let serve port handler =
  Lwt.async (fun () ->
      Server.create
        ~mode:(`TCP (`Port port))
        (Server.make ~callback:(fun _conn -> handler) ()))

let get = function
  | Ok v -> v
  | Error e -> Alcotest.failf "unexpected error: %a" Odoh.Error.pp e

(* A DoH resolver that answers every query with [dns_response]. *)
let resolver (request : Http.Request.t) body =
  let* query = Body.to_string body in
  let ok =
    request.meth = `POST
    && Http.Header.get request.headers "content-type"
       = Some "application/dns-message"
    && query = dns_query
  in
  if ok then
    Server.respond_string ~status:`OK
      ~headers:
        (Http.Header.of_list [ ("content-type", "application/dns-message") ])
      ~body:dns_response ()
  else Server.respond_string ~status:`Bad_request ~body:"" ()

let key = get (Odoh.Target.Key.generate ~rng Hpke.Kem.X25519)
let stale = get (Odoh.Target.Key.generate ~rng Hpke.Kem.X25519)
let config = Odoh.Target.Key.config key
let resolver_port = free_port ()
let target_port = free_port ()
let doh_target_port = free_port ()
let broken_target_port = free_port ()
let proxy_port = free_port ()
let small_proxy_port = free_port ()

let template =
  get
    (Odoh.Proxy.Template.parse
       "https://proxy.example/dns-query{?targethost,targetpath}")

(* The proxy reaches the targets over plain HTTP on this machine. *)
let route (t : Odoh.Proxy.target) =
  match t.host with
  | "target.example" -> Some (Uri.to_string (local target_port t.path))
  | "doh.example" -> Some (Uri.to_string (local doh_target_port t.path))
  | "broken.example" -> Some (Uri.to_string (local broken_target_port t.path))
  | "gone.example" -> Some (Uri.to_string (local (free_port ()) t.path))
  | _ -> None

let () =
  let service =
    Odoh.Service.Target.create ~rng (get (Odoh.Target.create [ key ]))
  in
  serve resolver_port resolver;
  serve target_port
    (O.Target.handler service (fun _ -> Lwt.return dns_response));
  serve doh_target_port
    (O.Target.handler service
       (C.Resolver.doh (local resolver_port "/dns-query")));
  serve broken_target_port
    (O.Target.handler service
       (C.Resolver.doh (local (free_port ()) "/dns-query")));
  serve proxy_port
    (C.Proxy.handler
       (Odoh.Service.Proxy.create ~name:"test-proxy" ~template ~route ()));
  serve small_proxy_port
    (C.Proxy.handler
       (Odoh.Service.Proxy.create ~max_message_size:64 ~template ~route ()))

(* Where a client posts its queries for [host]: the template's expansion, on the
   proxy on this machine. *)
let via ?(port = proxy_port) host =
  let expanded =
    Uri.of_string
      (Odoh.Proxy.Template.expand template ~targethost:host
         ~targetpath:"/dns-query")
  in
  Uri.with_query'
    (local port (Uri.path expanded))
    (List.map (fun (k, v) -> (k, String.concat "," v)) (Uri.query expanded))
  |> fun uri -> Uri.of_string (Uri.to_string uri)

let lwt name f = Alcotest.test_case name `Quick (fun () -> Lwt_main.run (f ()))

let test_configs () =
  let+ configs =
    C.Client.configs (local target_port Odoh.Service.well_known_configs_path)
  in
  match get configs with
  | [ c ] ->
      Alcotest.(check bool) "the target's" true (Odoh.Config.equal c config)
  | _ -> Alcotest.fail "one configuration"

let query ?port host config =
  C.Client.query ~rng ~proxy:(via ?port host) config dns_query

let test_query () =
  let+ answer = query "target.example" config in
  Alcotest.(check string) "response" dns_response (get answer)

let test_doh_resolver () =
  let+ answer = query "doh.example" config in
  Alcotest.(check string) "response" dns_response (get answer)

let test_servfail () =
  let+ answer = query "broken.example" config in
  Alcotest.(check string)
    "SERVFAIL"
    (Odoh.Service.servfail dns_query)
    (get answer)

let status name expected = function
  | Error (Odoh.Error.Unexpected_status s) ->
      Alcotest.(check int) name expected s
  | Ok _ -> Alcotest.failf "%s: answered" name
  | Error e -> Alcotest.failf "%s: %a" name Odoh.Error.pp e

let test_refusals () =
  let* denied = query "internal.example" config in
  status "denied" 403 denied;
  let* gone = query "gone.example" config in
  status "unreachable" 502 gone;
  let* stale = query "target.example" (Odoh.Target.Key.config stale) in
  status "stale configuration" 401 stale;
  let* large = query ~port:small_proxy_port "target.example" config in
  status "too large" 413 large;
  let* response, body =
    Cohttp_lwt_unix.Client.get (local proxy_port "/dns-query")
  in
  let* () = Body.drain_body body in
  Alcotest.(check int)
    "GET at the proxy" 405
    (Http.Status.to_int response.status);
  Alcotest.(check (option string))
    "proxy-status"
    (Some
       "test-proxy; error=http_request_error; details=\"method \\\"GET\\\" not \
        allowed\"")
    (Http.Header.get response.headers "proxy-status");
  let* response, body =
    Cohttp_lwt_unix.Client.get (local target_port "/elsewhere")
  in
  let+ () = Body.drain_body body in
  Alcotest.(check int)
    "404 at the target" 404
    (Http.Status.to_int response.status)

(* What the target sees of the client: only what the proxy chose to send. *)
let test_forwarded_fields () =
  let seen = ref [] in
  let spy_port = free_port () in
  serve spy_port (fun request body ->
      seen := Http.Header.to_list request.headers;
      let* () = Body.drain_body body in
      Server.respond_string ~status:`OK ~body:"" ());
  let proxy_port = free_port () in
  serve proxy_port
    (C.Proxy.handler
       (Odoh.Service.Proxy.create ~template
          ~route:(fun t -> Some (Uri.to_string (local spy_port t.path)))
          ()));
  let* () = Lwt_unix.sleep 0.1 in
  let* response, body =
    Cohttp_lwt_unix.Client.post
      ~headers:
        (Http.Header.of_list
           [
             ("content-type", "application/oblivious-dns-message");
             ("cookie", "session=1");
             ("authorization", "Bearer x");
             ("x-forwarded-for", "192.0.2.1");
             ("user-agent", "curious");
           ])
      ~body:(Body.of_string "query")
      (via ~port:proxy_port "spy.example")
  in
  let+ () = Body.drain_body body in
  Alcotest.(check int) "forwarded" 200 (Http.Status.to_int response.status);
  let seen = List.map (fun (k, v) -> (String.lowercase_ascii k, v)) !seen in
  List.iter
    (fun name ->
      Alcotest.(check bool)
        (name ^ " withheld") false (List.mem_assoc name seen))
    [ "cookie"; "authorization"; "x-forwarded-for" ];
  (* cohttp's client names itself; the client's own user-agent stays behind. *)
  Alcotest.(check bool)
    "user-agent withheld" false
    (List.assoc_opt "user-agent" seen = Some "curious")

let () =
  (* Let the servers start. *)
  Lwt_main.run (Lwt_unix.sleep 0.2);
  Alcotest.run "odoh-cohttp-lwt"
    [
      ( "exchange",
        [
          lwt "configurations" test_configs;
          lwt "query through the proxy" test_query;
          lwt "DoH resolver" test_doh_resolver;
          lwt "resolver failure" test_servfail;
          lwt "refusals" test_refusals;
          lwt "forwarded fields" test_forwarded_fields;
        ] );
    ]
