(* The test vectors of odoh-go, which odoh-rs checks too
   (test/vectors/odoh-go.json, from github.com/cloudflare/odoh-go at commit
   f39fa01, MIT licence). They do not record the client's ephemeral key, so a
   query cannot be reproduced; the target's side is reproduced byte for byte. *)

open Vectors
open Yojson.Safe.Util

let vectors () = load "odoh-go.json" |> to_list

let check_config v () =
  let configs = ok (Odoh.Config.decode_list (hex_field v "odohconfigs")) in
  let config =
    match configs with
    | [ c ] -> c
    | _ -> Alcotest.fail "expected one configuration"
  in
  check_bytes "key id" (hex_field v "key_id") (Odoh.Config.key_id config);
  check_bytes "re-encoded"
    (hex_field v "odohconfigs")
    (Odoh.Config.encode_list configs);
  let suite =
    ok
      (Odoh.Suite.of_ints ~kem:(int_field v "kem_id")
         ~kdf:(int_field v "kdf_id") ~aead:(int_field v "aead_id"))
  in
  Alcotest.(check bool)
    "suite" true
    (Odoh.Suite.equal suite (Odoh.Config.suite config));
  let key = key ~ikm:(hex_field v "public_key_seed") suite in
  Alcotest.(check bool)
    "derived key" true
    (Odoh.Config.equal config (Odoh.Target.Key.config key))

let check_transactions v () =
  let suite =
    ok
      (Odoh.Suite.of_ints ~kem:(int_field v "kem_id")
         ~kdf:(int_field v "kdf_id") ~aead:(int_field v "aead_id"))
  in
  let target =
    ok (Odoh.Target.create [ key ~ikm:(hex_field v "public_key_seed") suite ])
  in
  List.iteri
    (fun i t ->
      let name what = Printf.sprintf "transaction %d: %s" i what in
      let query, context =
        ok (Odoh.Target.decrypt_query target (hex_field t "obliviousQuery"))
      in
      check_bytes (name "query") (hex_field t "query") query;
      let expected = hex_field t "obliviousResponse" in
      let nonce = (ok (Odoh.Message.decode expected)).key_id in
      let response =
        ok
          (Odoh.Target.encrypt_response
             ~rng:(Fixed_rng.of_string nonce)
             ~padding:
               (Odoh.Message.Padding.fixed
                  (int_field t "responsePaddingLength"))
             context (hex_field t "response"))
      in
      check_bytes (name "response") expected response)
    (member "transactions" v |> to_list)

let tests =
  List.concat_map
    (fun v ->
      [
        Alcotest.test_case "configuration" `Quick (check_config v);
        Alcotest.test_case "transactions" `Quick (check_transactions v);
      ])
    (vectors ())
