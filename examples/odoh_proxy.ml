(* An Oblivious DoH proxy over cohttp-lwt-unix, over plain HTTP: put it behind
   something that terminates TLS. It forwards only to the targets given with
   --route, each to the base URI given for it: a route for HOST:PORT applies to
   that port, and one for HOST to any.

   odoh_proxy.exe --listen 8081 \ --template
   'https://proxy.example/proxy{?targethost,targetpath}' \ --route
   target.example=https://target.example *)

let () =
  let listen = ref 8081
  and template = ref "https://proxy.example/proxy{?targethost,targetpath}"
  and routes = ref [] in
  Arg.parse
    [
      ("--listen", Arg.Set_int listen, "PORT  port to listen on (8081)");
      ( "--template",
        Arg.Set_string template,
        "TEMPLATE  the proxy's URI template" );
      ( "--route",
        Arg.String
          (fun s ->
            match String.index_opt s '=' with
            | Some i ->
                routes :=
                  ( String.lowercase_ascii (String.sub s 0 i),
                    String.sub s (i + 1) (String.length s - i - 1) )
                  :: !routes
            | None -> raise (Arg.Bad "--route HOST=URI")),
        "HOST[:PORT]=URI  forward queries for HOST to URI, the path appended" );
    ]
    (fun a -> raise (Arg.Bad a))
    "odoh_proxy.exe --route HOST=URI [--template TEMPLATE] [--listen PORT]";
  let template =
    match Odoh.Proxy.Template.parse !template with
    | Ok t -> t
    | Error e -> failwith (Odoh.Error.to_string e)
  in
  (* A route for HOST:PORT is for that port only, one for HOST for any. *)
  let route (t : Odoh.Proxy.target) =
    let with_port =
      Option.map (fun p -> Printf.sprintf "%s:%d" t.host p) t.port
    in
    let base =
      match Option.bind with_port (fun k -> List.assoc_opt k !routes) with
      | Some base -> Some base
      | None -> List.assoc_opt t.host !routes
    in
    Option.map (fun base -> base ^ t.path) base
  in
  let module C = Odoh_cohttp_lwt.Make (Cohttp_lwt_unix.Client) in
  let handler =
    C.Proxy.handler (Odoh.Service.Proxy.create ~template ~route ())
  in
  Printf.printf "odoh proxy on port %d for %s\n%!" !listen
    (String.concat ", " (List.map fst !routes));
  Lwt_main.run
    (Cohttp_lwt_unix.Server.create
       ~mode:(`TCP (`Port !listen))
       (Cohttp_lwt_unix.Server.make ~callback:(fun _conn -> handler) ()))
