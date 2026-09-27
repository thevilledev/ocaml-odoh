(* One Oblivious DoH exchange between a client, a proxy, and a target, in one
   process and without HTTP: each step shows what would be sent. The DNS
   messages are fixed bytes, since odoh does not parse DNS; a real client would
   build them with a DNS library, and a real target would resolve them.

   dune exec examples/basic.exe *)

let get = function Ok v -> v | Error e -> failwith (Odoh.Error.to_string e)

let hex s =
  String.concat ""
    (List.init (String.length s) (fun i ->
         Printf.sprintf "%02x" (Char.code s.[i])))

let unhex h =
  String.init
    (String.length h / 2)
    (fun i -> Char.chr (int_of_string ("0x" ^ String.sub h (2 * i) 2)))

(* A query for the A record of example.com, and an answer to it. *)
let dns_query =
  unhex "abcd01000001000000000000076578616d706c6503636f6d0000010001"

let dns_response =
  unhex
    "abcd81800001000100000000076578616d706c6503636f6d0000010001c00c000100010000012c00045db8d722"

let () =
  Mirage_crypto_rng_unix.use_default ();
  let rng = Mirage_crypto_rng.default_generator () in

  (* The target generates a key, and publishes its configurations. *)
  let key = get (Odoh.Target.Key.generate ~rng Hpke.Kem.X25519) in
  let target = get (Odoh.Target.create [ key ]) in
  let published = Odoh.Target.encoded_configs target in
  Printf.printf "target publishes %d bytes of ObliviousDoHConfigs\n"
    (String.length published);

  (* The client reads them, and posts its query to the proxy's template. *)
  let config = List.hd (get (Odoh.Config.decode_list published)) in
  let template =
    get
      (Odoh.Proxy.Template.parse
         "https://dnsproxy.example/dns-query{?targethost,targetpath}")
  in
  let uri =
    Odoh.Proxy.Template.expand template ~targethost:"dnstarget.example"
      ~targetpath:"/dns-query"
  in
  let query, context = get (Odoh.Client.encrypt_query ~rng config dns_query) in
  Printf.printf "client posts %d bytes to %s\n" (String.length query) uri;

  (* The proxy checks the request and finds the target, without learning the
     query. *)
  let headers = Odoh.Http_binding.Client.request_headers in
  get (Odoh.Proxy.check_request ~meth:"POST" ~headers);
  let request_target =
    "/dns-query?targethost=dnstarget.example&targetpath=%2Fdns-query"
  in
  let t = get (Odoh.Proxy.target_of_request template request_target) in
  Printf.printf "proxy forwards it to %s\n" (Odoh.Proxy.target_uri t);

  (* The target decrypts the query, resolves it, and encrypts the answer. *)
  let headers = Odoh.Proxy.target_request_headers in
  get (Odoh.Http_binding.Target.check_request ~meth:"POST" ~headers);
  let received, response_context =
    get (Odoh.Target.decrypt_query target query)
  in
  Printf.printf "target received DNS query %s\n" (hex received);
  let response =
    get (Odoh.Target.encrypt_response ~rng response_context dns_response)
  in

  (* The proxy forwards the answer unchanged, and the client opens it. *)
  let headers =
    Odoh.Proxy.response_headers ~name:"dnsproxy.example" ~status:200
      ~headers:Odoh.Http_binding.Target.response_headers
  in
  List.iter
    (fun (k, v) -> Printf.printf "proxy answers with %s: %s\n" k v)
    headers;
  get (Odoh.Http_binding.Client.check_response ~status:200 ~headers);
  let answer = get (Odoh.Client.decrypt_response context response) in
  Printf.printf "client received DNS response %s\n" (hex answer)
