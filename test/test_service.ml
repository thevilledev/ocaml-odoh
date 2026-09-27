(* The client, proxy, and target as steps between HTTP messages. *)

open Vectors
module S = Odoh.Service

let template =
  ok
    (Odoh.Proxy.Template.parse
       "https://proxy.example/dns-query{?targethost,targetpath}")

let target_path = "/dns-query?targethost=target.example&targetpath=%2Fdns-query"
let odoh_ct = [ ("content-type", "application/oblivious-dns-message") ]

let setup () =
  let rng = rng () in
  let target = ok (Odoh.Target.create [ key Odoh.Suite.default ]) in
  let service = S.Target.create ~rng target in
  let proxy =
    S.Proxy.create ~name:"p" ~template
      ~route:(S.Proxy.allow [ "target.example" ])
      ()
  in
  (rng, service, proxy)

let header = Odoh.Http_binding.header

let test_exchange () =
  let rng, service, proxy = setup () in
  let configs = S.Target.configs service in
  let config =
    List.hd
      (ok
         (S.Client.configs ~status:configs.status ~headers:configs.headers
            configs.body))
  in
  let request, exchange = ok (S.Client.start ~rng config dns_query) in
  let uri, forwarded =
    match
      S.Proxy.request proxy ~meth:"POST"
        ~headers:
          (("cookie", "id=1")
          :: ("x-forwarded-for", "192.0.2.1")
          :: request.headers)
        ~target:target_path request.body
    with
    | Ok r -> r
    | Error r -> Alcotest.failf "proxy refused with %d" r.status
  in
  Alcotest.(check string) "target URI" "https://target.example/dns-query" uri;
  Alcotest.(check (option string))
    "no cookie" None
    (header forwarded.headers "cookie");
  Alcotest.(check (option string))
    "no forwarding" None
    (header forwarded.headers "x-forwarded-for");
  let answer =
    match
      S.Target.receive service ~meth:"POST" ~headers:forwarded.headers
        forwarded.body
    with
    | Resolve (query, seal) ->
        check_bytes "query" dns_query query;
        seal dns_response
    | Respond r -> Alcotest.failf "target answered %d" r.status
  in
  Alcotest.(check int) "target status" 200 answer.status;
  let relayed =
    S.Proxy.response proxy ~status:answer.status ~headers:answer.headers
      answer.body
  in
  Alcotest.(check (option string))
    "proxy-status" (Some "p; received-status=200")
    (header relayed.headers "proxy-status");
  check_bytes "response" dns_response
    (ok
       (S.Client.finish exchange ~status:relayed.status ~headers:relayed.headers
          relayed.body))

let status_of = function Ok _ -> 0 | Error (r : S.response) -> r.status

let test_proxy_refusals () =
  let _, _, proxy = setup () in
  let req ?(meth = "POST") ?(headers = odoh_ct) ?(target = target_path) body =
    status_of (S.Proxy.request proxy ~meth ~headers ~target body)
  in
  Alcotest.(check int) "GET" 405 (req ~meth:"GET" "x");
  Alcotest.(check int)
    "DoH" 415
    (req ~headers:[ ("content-type", "application/dns-message") ] "x");
  Alcotest.(check int) "no target" 400 (req ~target:"/dns-query" "x");
  Alcotest.(check int)
    "other host" 403
    (req ~target:"/dns-query?targethost=internal.example&targetpath=/x" "x");
  Alcotest.(check int)
    "other port" 403
    (req ~target:"/dns-query?targethost=target.example:8443&targetpath=/x" "x");
  Alcotest.(check int)
    "too large" 413
    (req (String.make (S.Proxy.max_message_size proxy + 1) 'x'));
  let long =
    S.Proxy.response proxy ~status:200 ~headers:odoh_ct
      (String.make (S.Proxy.max_message_size proxy + 1) 'x')
  in
  Alcotest.(check int) "long answer" 502 long.status;
  Alcotest.(check (option string))
    "body size" (Some "p; error=http_response_body_size")
    (header long.headers "proxy-status");
  let routed =
    S.Proxy.create ~template
      ~route:(S.Proxy.allow ~ports:[ 8443 ] [ "Target.Example" ])
      ()
  in
  Alcotest.(check int)
    "allowed port" 0
    (status_of
       (S.Proxy.request routed ~meth:"POST" ~headers:odoh_ct
          ~target:"/dns-query?targethost=target.example:8443&targetpath=/x" "x"))

let test_target_refusals () =
  let rng, service, _ = setup () in
  let respond = function S.Target.Respond r -> r.status | Resolve _ -> 200 in
  Alcotest.(check int)
    "GET" 405
    (respond (S.Target.receive service ~meth:"GET" ~headers:odoh_ct ""));
  Alcotest.(check int)
    "type" 415
    (respond (S.Target.receive service ~meth:"POST" ~headers:[] "x"));
  Alcotest.(check int)
    "garbage" 400
    (respond (S.Target.receive service ~meth:"POST" ~headers:odoh_ct "x"));
  let other =
    Odoh.Target.Key.config (key ~ikm:(String.make 64 'o') Odoh.Suite.default)
  in
  let request, _ = ok (S.Client.start ~rng other dns_query) in
  Alcotest.(check int)
    "unknown key" 401
    (respond
       (S.Target.receive service ~meth:"POST" ~headers:odoh_ct request.body));
  (* A DNS answer too long to encrypt is replaced with a SERVFAIL. *)
  let config =
    List.hd
      (Odoh.Target.configs (ok (Odoh.Target.create [ key Odoh.Suite.default ])))
  in
  let request, exchange = ok (S.Client.start ~rng config dns_query) in
  match S.Target.receive service ~meth:"POST" ~headers:odoh_ct request.body with
  | Respond r -> Alcotest.failf "answered %d" r.status
  | Resolve (_, seal) ->
      let r = seal (String.make 65535 'x') in
      let answer =
        ok (S.Client.finish exchange ~status:r.status ~headers:r.headers r.body)
      in
      check_bytes "servfail" (S.servfail dns_query) answer

let test_client_checks () =
  let rng, _, _ = setup () in
  let config = Odoh.Target.Key.config (key Odoh.Suite.default) in
  let _, exchange = ok (S.Client.start ~rng config dns_query) in
  check_error "401" (Odoh.Error.Unexpected_status 401)
    (S.Client.finish exchange ~status:401 ~headers:odoh_ct "");
  check_error "type" (Odoh.Error.Unexpected_content_type None)
    (S.Client.finish exchange ~status:200 ~headers:[] "");
  check_error "configs status" (Odoh.Error.Unexpected_status 404)
    (S.Client.configs ~status:404 ~headers:[] "")

let test_limits () =
  Alcotest.(check bool)
    "declared" true
    (S.exceeds ~max_size:10 [ ("content-length", "11") ]);
  Alcotest.(check bool)
    "fits" false
    (S.exceeds ~max_size:10 [ ("content-length", " 10 ") ]);
  Alcotest.(check bool)
    "unparsable" true
    (S.exceeds ~max_size:10 [ ("content-length", "ten") ]);
  Alcotest.(check bool) "undeclared" false (S.exceeds ~max_size:10 []);
  let a = S.Admission.create ~max_in_flight:2 in
  let first = S.Admission.admit a in
  let second = S.Admission.admit a in
  let third = S.Admission.admit a in
  Alcotest.(check (list bool))
    "admission" [ true; true; false ] [ first; second; third ];
  S.Admission.release a;
  Alcotest.(check bool) "released" true (S.Admission.admit a);
  Alcotest.check_raises "zero" (Invalid_argument "Odoh.Service: max_in_flight")
    (fun () -> ignore (S.Admission.create ~max_in_flight:0))

let test_servfail () =
  let r = S.servfail dns_query in
  (* The identifier, QR with RD kept, RA and SERVFAIL, one question. *)
  check_bytes "header"
    (Hex.decode "abcd81820001000000000000")
    (String.sub r 0 12);
  (* example.com is 13 bytes as labels, then the type and class. *)
  Alcotest.(check int) "question kept" (12 + 17) (String.length r);
  check_bytes "question" (String.sub dns_query 12 17) (String.sub r 12 17);
  check_bytes "short" (Hex.decode "000080820000000000000000") (S.servfail "xy");
  (* A compressed or truncated name leaves the question out. *)
  let truncated = String.sub dns_query 0 20 in
  Alcotest.(check int) "no question" 12 (String.length (S.servfail truncated))

let tests =
  [
    Alcotest.test_case "exchange" `Quick test_exchange;
    Alcotest.test_case "proxy refusals" `Quick test_proxy_refusals;
    Alcotest.test_case "target refusals" `Quick test_target_refusals;
    Alcotest.test_case "client checks" `Quick test_client_checks;
    Alcotest.test_case "limits" `Quick test_limits;
    Alcotest.test_case "servfail" `Quick test_servfail;
  ]
