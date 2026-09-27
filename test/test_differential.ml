(* Replays what tools/differential recorded against odoh-go and odoh-rs, so that
   the tests keep checking interoperability without the peers. *)

open Vectors
open Yojson.Safe.Util
module Fixtures = Odoh_test_support.Fixtures

let suite_of j =
  ok
    (Odoh.Suite.of_ints ~kem:(int_field j "kem") ~kdf:(int_field j "kdf")
       ~aead:(int_field j "aead"))

let target_of (suite : Odoh.Suite.t) n =
  let key =
    ok
      (Odoh.Target.Key.derive ~kdf:suite.kdf ~aead:suite.aead suite.kem
         ~ikm:(Fixtures.target_seed n))
  in
  (key, ok (Odoh.Target.create [ key ]))

(* The OCaml client rebuilds its query and opens the peer's response. *)
let client_case c =
  let suite = suite_of c and n = int_field c "case" in
  let key, _ = target_of suite n in
  let setup = ok (Fixtures.deterministic_setup suite n) in
  let query, context =
    ok
      (Odoh.Client.encrypt_query_with ~setup
         ~padding:(Odoh.Message.Padding.fixed (int_field c "query_padding"))
         (Odoh.Target.Key.config key)
         Fixtures.dns_query)
  in
  check_bytes "query" (hex_field c "query") query;
  check_bytes "response" Fixtures.dns_response
    (ok (Odoh.Client.decrypt_response context (hex_field c "response")))

(* The OCaml target opens the peer's query and rebuilds the response that the
   peer opened. *)
let target_case c =
  let suite = suite_of c and n = int_field c "case" in
  let _, target = target_of suite n in
  let query, context =
    ok (Odoh.Target.decrypt_query target (hex_field c "query"))
  in
  check_bytes "query" Fixtures.dns_query query;
  check_bytes "response" (hex_field c "response")
    (ok
       (Odoh.Target.encrypt_response
          ~rng:(Fixed_rng.of_string (hex_field c "nonce"))
          ~padding:(Odoh.Message.Padding.fixed (int_field c "response_padding"))
          context Fixtures.dns_response))

let peer file =
  let doc = load (Filename.concat "differential" file) in
  let name = member "implementation" (member "peer" doc) |> to_string in
  let cases role f () =
    let cases = member role doc |> to_list in
    if cases = [] then Alcotest.fail "no cases";
    List.iter f cases
  in
  [
    Alcotest.test_case (name ^ " as target") `Quick (cases "client" client_case);
    Alcotest.test_case (name ^ " as client") `Quick (cases "target" target_case);
  ]

let tests = List.concat_map peer [ "go.json"; "rust.json" ]
