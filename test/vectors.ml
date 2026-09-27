(* Helpers shared by the tests. *)

open Yojson.Safe.Util
module Hex = Odoh_test_support.Hex
module Fixed_rng = Odoh_test_support.Fixed_rng

let load name = Yojson.Safe.from_file (Filename.concat "vectors" name)
let string_field j k = to_string (member k j)
let int_field j k = to_int (member k j)
let hex_field j k = Hex.decode (string_field j k)

let octets =
  Alcotest.testable
    (fun fmt s -> Format.pp_print_string fmt (Hex.encode s))
    String.equal

(* Compare as hex so that a failure is readable. *)
let check_bytes name expected actual =
  Alcotest.check octets name expected actual

let error = Alcotest.testable Odoh.Error.pp ( = )

let ok = function
  | Ok v -> v
  | Error e -> Alcotest.failf "unexpected error: %a" Odoh.Error.pp e

let hpke_ok = function
  | Ok v -> v
  | Error e -> Alcotest.failf "unexpected HPKE error: %a" Hpke.Error.pp e

let check_error name expected = function
  | Ok _ -> Alcotest.failf "%s: expected %a" name Odoh.Error.pp expected
  | Error e -> Alcotest.check error name expected e

(* A generator that tests can repeat. Nothing here needs real entropy. *)
let rng () =
  Mirage_crypto_rng.create
    ~seed:(String.init 64 (fun i -> Char.chr (i + 1)))
    (module Mirage_crypto_rng.Fortuna)

(* Every KEM of the hpke package: the Diffie-Hellman KEMs of RFC 9180, the
   post-quantum/traditional hybrids, and ML-KEM. *)
let all_kems =
  Hpke.Kem.
    [
      X25519;
      X448;
      P256;
      P384;
      P521;
      Mlkem768_x25519;
      Mlkem768_p256;
      Mlkem1024_p384;
      Mlkem512;
      Mlkem768;
      Mlkem1024;
    ]

let all_kdfs = Hpke.Kdf.[ Hkdf_sha256; Hkdf_sha384; Hkdf_sha512 ]
let all_aeads = Hpke.Aead.[ Aes_128_gcm; Aes_256_gcm; Chacha20_poly1305 ]

let all_suites =
  List.concat_map
    (fun kem ->
      List.concat_map
        (fun kdf ->
          List.map (fun aead -> { Odoh.Suite.kem; kdf; aead }) all_aeads)
        all_kdfs)
    all_kems

let suite_name s = Format.asprintf "%a" Odoh.Suite.pp s

let key ?(ikm = String.make 64 '\x2a') (s : Odoh.Suite.t) =
  ok (Odoh.Target.Key.derive ~kdf:s.kdf ~aead:s.aead s.kem ~ikm)

let dns_query = Odoh_test_support.Fixtures.dns_query
let dns_response = Odoh_test_support.Fixtures.dns_response
