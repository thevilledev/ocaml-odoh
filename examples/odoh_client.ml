(* An Oblivious DoH client over cohttp-lwt-unix: fetches a target's
   configurations, and resolves one name through a proxy.

   odoh_client.exe --configs https://target.example/.well-known/odohconfigs \
   --template 'https://proxy.example/proxy{?targethost,targetpath}' \
   --targethost target.example example.com

   With --proxy-origin, the expanded URI is sent to that origin in place of the
   template's, such as a proxy on this machine without TLS. *)

let () =
  let configs = ref ""
  and template = ref ""
  and targethost = ref ""
  and targetpath = ref "/dns-query"
  and origin = ref ""
  and qtype = ref "A"
  and name = ref "" in
  Arg.parse
    [
      ("--configs", Arg.Set_string configs, "URI  where to fetch configurations");
      ( "--template",
        Arg.Set_string template,
        "TEMPLATE  the proxy's URI template" );
      ("--targethost", Arg.Set_string targethost, "HOST  the target's host");
      ("--targetpath", Arg.Set_string targetpath, "PATH  the target's path");
      ( "--proxy-origin",
        Arg.Set_string origin,
        "URI  send to this origin instead" );
      ("--type", Arg.Set_string qtype, "TYPE  A, AAAA, or TXT (A)");
    ]
    (fun a -> name := a)
    "odoh_client.exe --configs URI --template T --targethost HOST NAME";
  Mirage_crypto_rng_unix.use_default ();
  let rng = Mirage_crypto_rng.default_generator () in
  let module C = Odoh_cohttp_lwt.Make (Cohttp_lwt_unix.Client) in
  let fail e =
    Printf.eprintf "error: %s\n" (Odoh.Error.to_string e);
    exit 1
  in
  let get = function Ok v -> v | Error e -> fail e in
  let template = get (Odoh.Proxy.Template.parse !template) in
  let uri =
    Uri.of_string
      (Odoh.Proxy.Template.expand template ~targethost:!targethost
         ~targetpath:!targetpath)
  in
  let uri =
    if !origin = "" then uri
    else
      let o = Uri.of_string !origin in
      Uri.with_port
        (Uri.with_host (Uri.with_scheme uri (Uri.scheme o)) (Uri.host o))
        (Uri.port o)
  in
  let id =
    Random.self_init ();
    Random.int 0x10000
  in
  let query =
    Dns_wire.query ~id ~name:!name ~qtype:(Dns_wire.qtype_of_string !qtype)
  in
  Lwt_main.run
    (let open Lwt.Syntax in
     let* configs = C.Client.configs (Uri.of_string !configs) in
     let config =
       match get configs with c :: _ -> c | [] -> failwith "no configuration"
     in
     let+ answer = C.Client.query ~rng ~proxy:uri config query in
     let answer_id, rcode, answers = Dns_wire.answers (get answer) in
     if answer_id <> id then failwith "the answer is for another query";
     Printf.printf "%s %s %s: %s\n" !name !qtype rcode
       (String.concat " " answers))
