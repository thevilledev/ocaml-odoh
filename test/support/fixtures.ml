(* DNS messages for the tests and tools/differential. The library does not parse
   DNS, so any bytes would do; these are real ones, for the examples' sake: a
   query for the A record of example.com with EDNS(0), and its answer. *)

let dns_query =
  Hex.decode
    "abcd01000001000000000001076578616d706c6503636f6d00000100010000291000000000000000"

let dns_response =
  Hex.decode
    "abcd81800001000100000001076578616d706c6503636f6d0000010001c00c000100010000012c00045db8d7220000291000000000000000"

(* Input keying material for the target key and the client's ephemeral key of
   differential case [n], long enough for every KEM. *)
let seed ~role n =
  String.init 66 (fun i -> Char.chr (((i * 31) + (n * 7) + role) land 0xff))

let target_seed n = seed ~role:1 n
let ephemeral_seed n = seed ~role:2 n

(* The response nonce that the OCaml target uses in differential case [n]. *)
let response_nonce length n =
  String.init length (fun i -> Char.chr (((i * 13) + n) land 0xff))

(* The deterministic sender of differential case [n]: a query that the tests can
   rebuild byte for byte. *)
let deterministic_setup (suite : Odoh.Suite.t) n =
  match Hpke.derive_key_pair suite.kem ~ikm:(ephemeral_seed n) with
  | Error e -> Error (Odoh.Error.Hpke e)
  | Ok (ephemeral, _) ->
      Ok
        (fun hpke_suite ~recipient ~info ->
          Hpke_for_testing.setup_base_sender hpke_suite ~ephemeral ~recipient
            ~info)
