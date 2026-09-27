(* Properties over random input: nothing that reads a peer's bytes raises, and
   what is encoded decodes to what it came from. *)

open Vectors
module Gen = QCheck2.Gen

let bytes_gen = Gen.string_size ~gen:Gen.char (Gen.int_range 0 300)
let target = ok (Odoh.Target.create [ key Odoh.Suite.default ])
let config = List.hd (Odoh.Target.configs target)

let template =
  ok (Odoh.Proxy.Template.parse "https://p.example/q{?targethost,targetpath}")

let total name f =
  QCheck2.Test.make ~count:2000 ~name ~print:Hex.encode bytes_gen (fun s ->
      match f s with Ok _ | Error _ -> true)

let message_gen =
  Gen.map3
    (fun ty key_id m ->
      {
        Odoh.Message.message_type = (if ty then Query else Response);
        key_id;
        encrypted_message = "x" ^ m;
      })
    Gen.bool bytes_gen bytes_gen

let message_roundtrip =
  QCheck2.Test.make ~count:1000 ~name:"message roundtrip" message_gen (fun m ->
      Odoh.Message.decode (Odoh.Message.encode m) = Ok m)

let padding_gen =
  Gen.oneof
    [
      Gen.return Odoh.Message.Padding.none;
      Gen.map Odoh.Message.Padding.fixed (Gen.int_range 0 600);
      Gen.map Odoh.Message.Padding.block (Gen.int_range 1 600);
    ]

let exchange_roundtrip =
  let rng = rng () in
  QCheck2.Test.make ~count:300 ~name:"exchange roundtrip"
    Gen.(tup4 bytes_gen bytes_gen padding_gen padding_gen)
    (fun (q, r, qp, rp) ->
      let q = "q" ^ q and r = "r" ^ r in
      let query, client =
        ok (Odoh.Client.encrypt_query ~rng ~padding:qp config q)
      in
      let received, context = ok (Odoh.Target.decrypt_query target query) in
      let response =
        ok (Odoh.Target.encrypt_response ~rng ~padding:rp context r)
      in
      received = q && Odoh.Client.decrypt_response client response = Ok r)

(* Bytes appended to or cut from an honest query never decrypt. *)
let query_malleability =
  let rng = rng () in
  let query, _ = ok (Odoh.Client.encrypt_query ~rng config dns_query) in
  QCheck2.Test.make ~count:500 ~name:"altered queries are refused"
    Gen.(pair (int_range 0 (String.length query - 1)) bytes_gen)
    (fun (cut, extra) ->
      let altered = String.sub query 0 cut ^ extra in
      altered = query
      ||
      match Odoh.Target.decrypt_query target altered with
      | Ok _ -> false
      | Error _ -> true)

let host_gen =
  Gen.oneof
    [
      Gen.map
        (fun labels -> String.concat "." labels)
        (Gen.list_size (Gen.int_range 1 4)
           (Gen.string_size ~gen:(Gen.char_range 'a' 'z') (Gen.int_range 1 10)));
      Gen.map
        (fun (a, b) -> Printf.sprintf "192.0.%d.%d" a b)
        Gen.(pair (int_range 0 255) (int_range 0 255));
    ]

let path_gen =
  let pchar =
    Gen.oneof
      [
        Gen.char_range 'a' 'z';
        Gen.char_range '0' '9';
        Gen.oneof
          (List.map Gen.return
             [
               '-';
               '_';
               '~';
               '!';
               '$';
               '&';
               '\'';
               '(';
               ')';
               '*';
               '+';
               ',';
               ';';
               '=';
               ':';
               '@';
             ]);
      ]
  in
  Gen.map
    (fun segments -> "/" ^ String.concat "/" segments)
    (Gen.list_size (Gen.int_range 1 4)
       (Gen.string_size ~gen:pchar (Gen.int_range 1 8)))

let template_roundtrip =
  QCheck2.Test.make ~count:1000 ~name:"template expand and match"
    ~print:(fun (h, p, port) ->
      Printf.sprintf "%s %s %s" h p
        (match port with None -> "" | Some p -> string_of_int p))
    Gen.(
      triple host_gen path_gen
        (oneof [ return None; map Option.some (int_range 1 65535) ]))
    (fun (host, path, port) ->
      let targethost =
        match port with None -> host | Some p -> host ^ ":" ^ string_of_int p
      in
      let uri =
        Odoh.Proxy.Template.expand template ~targethost ~targetpath:path
      in
      let request = String.sub uri 17 (String.length uri - 17) in
      (* Dot segments are refused; the generator can make "." only as part of a
         longer segment, and never ".." alone. *)
      Odoh.Proxy.target_of_request template request
      = Ok { Odoh.Proxy.host; port; path })

let tests =
  List.map QCheck_alcotest.to_alcotest
    [
      total "Config.decode_list is total" Odoh.Config.decode_list;
      total "Config.decode is total" Odoh.Config.decode;
      total "Message.decode is total" Odoh.Message.decode;
      total "Plaintext.decode is total" Odoh.Message.Plaintext.decode;
      total "Target.decrypt_query is total" (Odoh.Target.decrypt_query target);
      total "Proxy.target_of_request is total"
        (Odoh.Proxy.target_of_request template);
      total "Template.parse is total" Odoh.Proxy.Template.parse;
      message_roundtrip;
      exchange_roundtrip;
      query_malleability;
      template_roundtrip;
    ]
