(* An Oblivious DoH target over cohttp-lwt-unix, in front of a DNS over HTTPS
   resolver. It serves its configurations at /.well-known/odohconfigs and
   queries at /dns-query, over plain HTTP: put it behind something that
   terminates TLS.

   odoh_target.exe --listen 8080 --resolver https://dns.example/dns-query *)

let () =
  let listen = ref 8080 and resolver = ref "" and path = ref "/dns-query" in
  Arg.parse
    [
      ("--listen", Arg.Set_int listen, "PORT  port to listen on (8080)");
      ("--resolver", Arg.Set_string resolver, "URI  DoH resolver to forward to");
      ("--path", Arg.Set_string path, "PATH  path of queries (/dns-query)");
    ]
    (fun a -> raise (Arg.Bad a))
    "odoh_target.exe --resolver URI [--listen PORT]";
  if !resolver = "" then (
    prerr_endline "--resolver is required";
    exit 2);
  Mirage_crypto_rng_unix.use_default ();
  let rng = Mirage_crypto_rng.default_generator () in
  let get = function
    | Ok v -> v
    | Error e -> failwith (Odoh.Error.to_string e)
  in
  let key = get (Odoh.Target.Key.generate ~rng Hpke.Kem.X25519) in
  let service =
    Odoh.Service.Target.create ~rng (get (Odoh.Target.create [ key ]))
  in
  let module C = Odoh_cohttp_lwt.Make (Cohttp_lwt_unix.Client) in
  let handler =
    Odoh_cohttp_lwt.Target.handler ~path:!path service
      (C.Resolver.doh (Uri.of_string !resolver))
  in
  Printf.printf "odoh target on port %d, resolving with %s\n%!" !listen
    !resolver;
  Lwt_main.run
    (Cohttp_lwt_unix.Server.create
       ~mode:(`TCP (`Port !listen))
       (Cohttp_lwt_unix.Server.make ~callback:(fun _conn -> handler) ()))
