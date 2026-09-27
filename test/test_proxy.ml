(* The HTTP binding and the proxy (RFC 9230 Section 4). *)

open Vectors
module Proxy = Odoh.Proxy
module Template = Odoh.Proxy.Template

let query_template =
  "https://dnsproxy.example/dns-query{?targethost,targetpath}"

let path_template = "https://dnsproxy.example/{targethost}/{targetpath}"
let template s = ok (Template.parse s)

let target =
  Alcotest.testable
    (fun fmt (t : Proxy.target) ->
      Format.fprintf fmt "{ host = %S; port = %s; path = %S }" t.host
        (match t.port with None -> "None" | Some p -> string_of_int p)
        t.path)
    ( = )

let dnstarget =
  { Proxy.host = "dnstarget.example"; port = None; path = "/dns-query" }

let test_expand () =
  let check name t expected =
    Alcotest.(check string)
      name expected
      (Template.expand (template t) ~targethost:"dnstarget.example"
         ~targetpath:"/dns-query")
  in
  check "query" query_template
    "https://dnsproxy.example/dns-query?targethost=dnstarget.example&targetpath=%2Fdns-query";
  check "path" path_template
    "https://dnsproxy.example/dnstarget.example/%2Fdns-query";
  check "reserved" "https://p.example/{+targethost}{+targetpath}"
    "https://p.example/dnstarget.example/dns-query";
  check "path operator" "https://p.example{/targethost,targetpath}"
    "https://p.example/dnstarget.example/%2Fdns-query";
  check "parameters" "https://p.example/q{;targethost,targetpath}"
    "https://p.example/q;targethost=dnstarget.example;targetpath=%2Fdns-query";
  check "continuation" "https://p.example/q?v=1{&targetpath,targethost}"
    "https://p.example/q?v=1&targetpath=%2Fdns-query&targethost=dnstarget.example";
  check "no path" "https://p.example{?targethost,targetpath}"
    "https://p.example?targethost=dnstarget.example&targetpath=%2Fdns-query";
  check "comma list" "https://p.example/{targethost,targetpath}"
    "https://p.example/dnstarget.example,%2Fdns-query"

(* Whatever a template expands to, the proxy reads the same target back. *)
let test_roundtrip () =
  List.iter
    (fun t ->
      let tpl = template t in
      List.iter
        (fun (host, port, path) ->
          let targethost =
            match port with
            | None -> host
            | Some p -> host ^ ":" ^ string_of_int p
          in
          let uri = Template.expand tpl ~targethost ~targetpath:path in
          (* The request target: the URI without scheme and authority. *)
          let origin_length = String.index_from uri 8 '/' in
          let request =
            match String.index_from_opt uri 8 '/' with
            | Some _ ->
                String.sub uri origin_length (String.length uri - origin_length)
            | None -> "/"
          in
          Alcotest.check
            (Alcotest.result target error)
            (Printf.sprintf "%s: %s" t request)
            (Ok { Proxy.host; port; path })
            (Proxy.target_of_request tpl request))
        [
          ("dnstarget.example", None, "/dns-query");
          ("dnstarget.example", Some 8443, "/a/b;c=d,e");
          ("[2001:db8::1]", Some 443, "/");
          ("192.0.2.1", None, "/dns-query");
        ])
    [
      query_template;
      path_template;
      "https://p.example/x/{+targethost}{+targetpath}";
      "https://p.example{/targethost,targetpath}";
      "https://p.example/q{;targethost,targetpath}";
      "https://p.example/q?v=1{&targetpath,targethost}";
      "https://p.example/{targethost}{?targetpath}";
    ]

let test_target_of_request () =
  let t = template query_template in
  let check name request expected =
    Alcotest.check
      (Alcotest.result target error)
      name expected
      (Proxy.target_of_request t request)
  in
  let invalid name request =
    match Proxy.target_of_request t request with
    | Error (Odoh.Error.Invalid_target _) -> ()
    | Ok _ | Error _ -> Alcotest.failf "%s: expected Invalid_target" name
  in
  check "RFC 9230 Section 4.2"
    "/dns-query?targethost=dnstarget.example&targetpath=/dns-query"
    (Ok dnstarget);
  check "encoded"
    "/dns-query?targethost=dnstarget.example&targetpath=%2Fdns-query"
    (Ok dnstarget);
  check "reordered"
    "/dns-query?targetpath=%2Fdns-query&targethost=DNSTarget.Example"
    (Ok dnstarget);
  check "port"
    "/dns-query?targethost=dnstarget.example%3A8443&targetpath=/dns-query"
    (Ok { dnstarget with port = Some 8443 });
  (* A path that holds a percent-encoded character survives when the client
     encodes it again, as expansion other than reserved does. *)
  check "encoded twice"
    "/dns-query?targethost=dnstarget.example&targetpath=%2Fa%252Fb"
    (Ok { dnstarget with path = "/a%2Fb" });
  check "trailing dot"
    "/dns-query?targethost=dnstarget.example.&targetpath=/dns-query"
    (Ok { dnstarget with host = "dnstarget.example." });
  List.iter
    (fun (name, r) -> invalid name r)
    [
      ("other path", "/other?targethost=dnstarget.example&targetpath=/dns-query");
      ("missing path", "/dns-query?targethost=dnstarget.example");
      ("extra variable", "/dns-query?targethost=d.example&targetpath=/q&x=1");
      ("duplicate", "/dns-query?targethost=d.example&targethost=d.example");
      ("no query", "/dns-query");
      ("userinfo", "/dns-query?targethost=user%40d.example&targetpath=/q");
      ("empty host", "/dns-query?targethost=&targetpath=/q");
      ("port zero", "/dns-query?targethost=d.example:0&targetpath=/q");
      ("port too large", "/dns-query?targethost=d.example:65536&targetpath=/q");
      ("relative path", "/dns-query?targethost=d.example&targetpath=q");
      ("dot segment", "/dns-query?targethost=d.example&targetpath=/a/../q");
      ("query in path", "/dns-query?targethost=d.example&targetpath=/q%3Fx");
      ("fragment in path", "/dns-query?targethost=d.example&targetpath=/q%23x");
      ("space in path", "/dns-query?targethost=d.example&targetpath=/q%20x");
      ("bad encoding", "/dns-query?targethost=d.example&targetpath=/q%2");
      ("host with slash", "/dns-query?targethost=d.example%2Fx&targetpath=/q");
      ("bad IPv6", "/dns-query?targethost=%5Bxyz%5D&targetpath=/q");
      ( "label too long",
        "/dns-query?targethost=" ^ String.make 64 'a' ^ "&targetpath=/q" );
      ("empty label", "/dns-query?targethost=a..b&targetpath=/q");
    ];
  let p = template path_template in
  Alcotest.check
    (Alcotest.result target error)
    "path template" (Ok dnstarget)
    (Proxy.target_of_request p "/dnstarget.example/%2Fdns-query");
  (match Proxy.target_of_request p "/dnstarget.example/%2Fdns-query?x" with
  | Error (Odoh.Error.Invalid_target _) -> ()
  | _ -> Alcotest.fail "a query after a path template");
  Alcotest.(check string)
    "target URI" "https://dnstarget.example:8443/dns-query"
    (Proxy.target_uri { dnstarget with port = Some 8443 })

let test_invalid_templates () =
  List.iter
    (fun t ->
      match Template.parse t with
      | Error (Odoh.Error.Invalid_template _) -> ()
      | Ok _ | Error _ -> Alcotest.failf "%S should be refused" t)
    [
      "http://p.example/dns-query{?targethost,targetpath}";
      "https://p.example/dns-query{?targethost}";
      "https://p.example/dns-query{?targethost,targetpath,x}";
      "https://p.example/{targethost}/{targethost}/{targetpath}";
      "https://p.example/dns-query{?targethost,targetpath}#f";
      "https://p.example/dns-query{#targethost,targetpath}";
      "https://p.example/{.targethost}{/targetpath}";
      "https://p.example/{targethost:3}/{targetpath}";
      "https://p.example/{targethost*}/{targetpath}";
      "https://{targethost}/{targetpath}";
      "https://p.example{targethost}/{targetpath}";
      "https://p.example/{targethost}{targetpath}";
      "https://p.example/{targethost/{targetpath}";
      "https://p.example/ {targethost}/{targetpath}";
      "https://p.example/}{targethost}/{targetpath}";
      "https:///{targethost}/{targetpath}";
      "https://p.example/{}/{targethost}/{targetpath}";
    ];
  Alcotest.(check string)
    "to_string" query_template
    (Template.to_string (template query_template));
  ignore (template "HTTPS://p.example/{targethost}/{targetpath}")

let test_proxy_status () =
  Alcotest.(check string)
    "received" "proxy.example; received-status=200"
    (Proxy.proxy_status ~name:"proxy.example" ~received_status:200 ());
  Alcotest.(check string)
    "error" "\"my proxy\"; error=http_request_denied; details=\"a \\\"b\\\" ?\""
    (Proxy.proxy_status ~name:"my proxy" ~error:"http_request_denied"
       ~details:"a \"b\" \n" ());
  Alcotest.check_raises "error must be a token"
    (Invalid_argument "Odoh.Proxy.proxy_status: error") (fun () ->
      ignore (Proxy.proxy_status ~name:"p" ~error:"not a token" ()))

let test_headers () =
  let find = Odoh.Http_binding.header in
  let fields =
    Proxy.response_headers ~name:"p" ~status:401
      ~headers:
        [
          ("Content-Type", "application/oblivious-dns-message");
          ("set-cookie", "a=b");
          ("server", "target");
        ]
  in
  Alcotest.(check (option string))
    "content type" (Some "application/oblivious-dns-message")
    (find fields "content-type");
  Alcotest.(check (option string))
    "proxy status" (Some "p; received-status=401")
    (find fields "proxy-status");
  Alcotest.(check (option string)) "no cookie" None (find fields "set-cookie");
  Alcotest.(check (option string)) "no server" None (find fields "server");
  Alcotest.(check (list (pair string string)))
    "to the target"
    [
      ("content-type", "application/oblivious-dns-message");
      ("accept", "application/oblivious-dns-message");
    ]
    Proxy.target_request_headers;
  let e = Proxy.error_response ~name:"p" (Odoh.Error.Invalid_target "x") in
  Alcotest.(check int) "malformed" 400 e.status;
  Alcotest.(check (option string))
    "request error"
    (Some "p; error=http_request_error; details=\"invalid target: x\"")
    (find e.headers "proxy-status");
  Alcotest.(check int)
    "method" 405
    (Proxy.error_response ~name:"p" (Odoh.Error.Method_not_allowed "GET"))
      .status;
  Alcotest.(check int) "denied" 403 (Proxy.denied ~name:"p" ()).status;
  let u = Proxy.unreachable ~name:"p" ~error:"dns_timeout" () in
  Alcotest.(check int) "unreachable" 502 u.status;
  Alcotest.(check (option string))
    "dns timeout" (Some "p; error=dns_timeout")
    (find u.headers "proxy-status")

let test_binding () =
  let open Odoh.Http_binding in
  let ct = [ ("Content-Type", "Application/Oblivious-DNS-Message; x=y") ] in
  Alcotest.(check bool)
    "target accepts" true
    (Target.check_request ~meth:"POST" ~headers:ct = Ok ());
  check_error "GET" (Odoh.Error.Method_not_allowed "GET")
    (Target.check_request ~meth:"GET" ~headers:ct);
  check_error "no type" (Odoh.Error.Unsupported_media_type None)
    (Target.check_request ~meth:"POST" ~headers:[]);
  check_error "DoH type"
    (Odoh.Error.Unsupported_media_type (Some "application/dns-message"))
    (Proxy.check_request ~meth:"POST"
       ~headers:[ ("content-type", "application/dns-message") ]);
  Alcotest.(check bool)
    "client accepts" true
    (Client.check_response ~status:200 ~headers:ct = Ok ());
  check_error "401" (Odoh.Error.Unexpected_status 401)
    (Client.check_response ~status:401 ~headers:ct);
  check_error "wrong type"
    (Odoh.Error.Unexpected_content_type (Some "text/plain"))
    (Client.check_response ~status:200
       ~headers:[ ("content-type", "text/plain") ]);
  let status e = (Target.error_response e).status in
  Alcotest.(check int) "unknown key" 401 (status Odoh.Error.Unknown_key_id);
  Alcotest.(check int) "decryption" 400 (status Odoh.Error.Decryption_failed);
  Alcotest.(check int)
    "type" 415
    (status (Odoh.Error.Unsupported_media_type None));
  Alcotest.(check int)
    "internal" 500
    (status (Odoh.Error.Hpke Hpke.Error.Open_error));
  Alcotest.(check bool)
    "bound" true
    (max_message_length = 1 + 2 + 65535 + 2 + 65535)

let tests =
  [
    Alcotest.test_case "expand" `Quick test_expand;
    Alcotest.test_case "expand and match" `Quick test_roundtrip;
    Alcotest.test_case "target of request" `Quick test_target_of_request;
    Alcotest.test_case "invalid templates" `Quick test_invalid_templates;
    Alcotest.test_case "proxy-status" `Quick test_proxy_status;
    Alcotest.test_case "forwarded fields" `Quick test_headers;
    Alcotest.test_case "HTTP binding" `Quick test_binding;
  ]
