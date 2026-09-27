(* Queries and responses between a client and a target (RFC 9230 Sections 7 and
   8), over every suite of the hpke package. *)

open Vectors

let exchange ?query_padding ?response_padding suite =
  let rng = rng () in
  let target = ok (Odoh.Target.create [ key suite ]) in
  let config = List.hd (Odoh.Target.configs target) in
  let query, client =
    ok (Odoh.Client.encrypt_query ~rng ?padding:query_padding config dns_query)
  in
  let received, context = ok (Odoh.Target.decrypt_query target query) in
  let response =
    ok
      (Odoh.Target.encrypt_response ~rng ?padding:response_padding context
         dns_response)
  in
  (target, query, client, received, response)

let roundtrip suite () =
  let _, query, client, received, response = exchange suite in
  check_bytes "query" dns_query received;
  check_bytes "response" dns_response
    (ok (Odoh.Client.decrypt_response client response));
  let m = ok (Odoh.Message.decode query) in
  Alcotest.(check bool) "query type" true (m.message_type = Query);
  let r = ok (Odoh.Message.decode response) in
  Alcotest.(check int)
    "response nonce"
    (Odoh.Suite.response_nonce_length suite)
    (String.length r.key_id)

let test_default_padding () =
  let _, query, _, _, response = exchange Odoh.Suite.default in
  let m = ok (Odoh.Message.decode query) in
  (* enc (32) and the AEAD tag (16) around a plaintext of 128 bytes. *)
  Alcotest.(check int)
    "query"
    (32 + 128 + 16)
    (String.length m.encrypted_message);
  let r = ok (Odoh.Message.decode response) in
  Alcotest.(check int) "response" (468 + 16) (String.length r.encrypted_message)

let test_no_padding () =
  let _, query, client, _, response =
    exchange ~query_padding:Odoh.Message.Padding.none
      ~response_padding:Odoh.Message.Padding.none Odoh.Suite.default
  in
  let m = ok (Odoh.Message.decode query) in
  Alcotest.(check int)
    "query"
    (32 + 4 + String.length dns_query + 16)
    (String.length m.encrypted_message);
  check_bytes "response" dns_response
    (ok (Odoh.Client.decrypt_response client response))

let flip s i =
  String.mapi (fun j c -> if i = j then Char.chr (Char.code c lxor 1) else c) s

let test_tampering () =
  let target, query, client, _, response = exchange Odoh.Suite.default in
  let m = ok (Odoh.Message.decode query) in
  (* Every byte of the encrypted query is authenticated, and so is the key
     identifier through the additional data. *)
  for i = 0 to String.length m.encrypted_message - 1 do
    let q =
      Odoh.Message.encode
        { m with encrypted_message = flip m.encrypted_message i }
    in
    check_error "tampered query" Odoh.Error.Decryption_failed
      (Odoh.Target.decrypt_query target q)
  done;
  check_error "unknown key" Odoh.Error.Unknown_key_id
    (Odoh.Target.decrypt_query target
       (Odoh.Message.encode { m with key_id = flip m.key_id 0 }));
  check_error "short query" Odoh.Error.Decryption_failed
    (Odoh.Target.decrypt_query target
       (Odoh.Message.encode { m with encrypted_message = "short" }));
  check_error "response as query" (Odoh.Error.Unexpected_message_type 2)
    (Odoh.Target.decrypt_query target response);
  let r = ok (Odoh.Message.decode response) in
  for i = 0 to String.length r.encrypted_message - 1 do
    check_error "tampered response" Odoh.Error.Decryption_failed
      (Odoh.Client.decrypt_response client
         (Odoh.Message.encode
            { r with encrypted_message = flip r.encrypted_message i }))
  done;
  for i = 0 to String.length r.key_id - 1 do
    check_error "tampered nonce" Odoh.Error.Decryption_failed
      (Odoh.Client.decrypt_response client
         (Odoh.Message.encode { r with key_id = flip r.key_id i }))
  done;
  check_error "short nonce" Odoh.Error.Decryption_failed
    (Odoh.Client.decrypt_response client
       (Odoh.Message.encode { r with key_id = String.sub r.key_id 1 15 }));
  check_error "query as response" (Odoh.Error.Unexpected_message_type 1)
    (Odoh.Client.decrypt_response client query)

(* A response answers one query: another query's context does not open it. *)
let test_binding () =
  let rng = rng () in
  let target = ok (Odoh.Target.create [ key Odoh.Suite.default ]) in
  let config = List.hd (Odoh.Target.configs target) in
  let q1, c1 = ok (Odoh.Client.encrypt_query ~rng config dns_query) in
  let _, c2 = ok (Odoh.Client.encrypt_query ~rng config dns_query) in
  Alcotest.(check bool)
    "fresh encapsulation" false
    (String.equal q1
       (fst (ok (Odoh.Client.encrypt_query ~rng config dns_query))));
  let _, t1 = ok (Odoh.Target.decrypt_query target q1) in
  let r1 = ok (Odoh.Target.encrypt_response ~rng t1 dns_response) in
  check_bytes "own context" dns_response
    (ok (Odoh.Client.decrypt_response c1 r1));
  check_error "other context" Odoh.Error.Decryption_failed
    (Odoh.Client.decrypt_response c2 r1)

let test_rotation () =
  let old_key = key Odoh.Suite.default in
  let new_key = key ~ikm:(String.make 64 '\x07') Odoh.Suite.default in
  let rotated = ok (Odoh.Target.create [ new_key; old_key ]) in
  let rng = rng () in
  List.iter
    (fun k ->
      let q, _ =
        ok (Odoh.Client.encrypt_query ~rng (Odoh.Target.Key.config k) dns_query)
      in
      check_bytes "query" dns_query
        (fst (ok (Odoh.Target.decrypt_query rotated q))))
    [ old_key; new_key ];
  let only_new = ok (Odoh.Target.create [ new_key ]) in
  let q, _ =
    ok
      (Odoh.Client.encrypt_query ~rng
         (Odoh.Target.Key.config old_key)
         dns_query)
  in
  check_error "retired key" Odoh.Error.Unknown_key_id
    (Odoh.Target.decrypt_query only_new q);
  check_error "duplicate key" (Odoh.Error.Invalid_config "duplicate key")
    (Odoh.Target.create [ old_key; old_key ]);
  check_error "no keys" (Odoh.Error.Invalid_config "no keys")
    (Odoh.Target.create []);
  (* The same key with another AEAD is another configuration. *)
  let aes256 =
    ok
      (Odoh.Target.Key.derive ~aead:Hpke.Aead.Aes_256_gcm Hpke.Kem.X25519
         ~ikm:(String.make 64 '\x2a'))
  in
  ignore (ok (Odoh.Target.create [ old_key; aes256 ]));
  let configs = Odoh.Target.configs rotated in
  Alcotest.(check int)
    "published" 2
    (List.length
       (ok (Odoh.Config.decode_list (Odoh.Target.encoded_configs rotated))));
  Alcotest.(check bool)
    "preference order" true
    (Odoh.Config.equal (List.hd configs) (Odoh.Target.Key.config new_key))

let test_limits () =
  let rng = rng () in
  let config = Odoh.Target.Key.config (key Odoh.Suite.default) in
  check_error "empty query" (Odoh.Error.Invalid_dns_message "empty")
    (Odoh.Client.encrypt_query ~rng config "");
  (* 65535 bytes of DNS message do not fit with enc and a tag. *)
  check_error "too long" (Odoh.Error.Invalid_dns_message "too long")
    (Odoh.Client.encrypt_query ~rng ~padding:Odoh.Message.Padding.none config
       (String.make 65535 'x'));
  let _, context =
    ok
      (Odoh.Target.decrypt_query
         (ok (Odoh.Target.create [ key Odoh.Suite.default ]))
         (fst (ok (Odoh.Client.encrypt_query ~rng config dns_query))))
  in
  check_error "response too long" (Odoh.Error.Invalid_dns_message "too long")
    (Odoh.Target.encrypt_response ~rng ~padding:Odoh.Message.Padding.none
       context (String.make 65535 'x'))

let tests =
  [
    Alcotest.test_case "default padding" `Quick test_default_padding;
    Alcotest.test_case "no padding" `Quick test_no_padding;
    Alcotest.test_case "tampering" `Quick test_tampering;
    Alcotest.test_case "response binding" `Quick test_binding;
    Alcotest.test_case "key rotation" `Quick test_rotation;
    Alcotest.test_case "limits" `Quick test_limits;
  ]
  @ List.map
      (fun s -> Alcotest.test_case (suite_name s) `Quick (roundtrip s))
      all_suites
