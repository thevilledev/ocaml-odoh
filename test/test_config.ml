(* Target configurations and their three encodings (RFC 9230 Section 5). *)

open Vectors
module Config = Odoh.Config
module Hex = Odoh_test_support.Hex

let u16 n = Printf.sprintf "%c%c" (Char.chr (n lsr 8)) (Char.chr (n land 0xff))
let opaque16 s = u16 (String.length s) ^ s
let config ?(suite = Odoh.Suite.default) () = Odoh.Target.Key.config (key suite)
let versioned ?(version = 1) contents = u16 version ^ opaque16 contents
let list configs = opaque16 (String.concat "" configs)

let test_create () =
  let c = config () in
  Alcotest.(check bool)
    "default suite" true
    (Odoh.Suite.equal (Config.suite c) Odoh.Suite.default);
  Alcotest.(check int) "key id is Nh" 32 (String.length (Config.key_id c));
  let c384 =
    config ~suite:{ Odoh.Suite.default with kdf = Hpke.Kdf.Hkdf_sha384 } ()
  in
  Alcotest.(check int)
    "key id with SHA-384" 48
    (String.length (Config.key_id c384));
  Alcotest.(check bool)
    "key id depends on the KDF" false
    (String.equal (Config.key_id c) (Config.key_id c384))

let test_layout () =
  let c = config () in
  let pk = Hpke.Public_key.to_bytes (Config.public_key c) in
  let contents = u16 0x20 ^ u16 1 ^ u16 1 ^ opaque16 pk in
  check_bytes "contents" contents (Config.encode_contents c);
  check_bytes "config" (versioned contents) (Config.encode c);
  check_bytes "list" (list [ versioned contents ]) (Config.encode_list [ c ])

let roundtrip suite () =
  let c = config ~suite () in
  let eq = Alcotest.testable Config.pp Config.equal in
  Alcotest.check (Alcotest.result eq error) "contents" (Ok c)
    (Config.decode_contents (Config.encode_contents c));
  Alcotest.check (Alcotest.result eq error) "config" (Ok c)
    (Config.decode (Config.encode c));
  Alcotest.check
    (Alcotest.result (Alcotest.list eq) error)
    "list"
    (Ok [ c; c ])
    (Config.decode_list (Config.encode_list [ c; c ]));
  let decoded = ok (Config.decode (Config.encode c)) in
  check_bytes "key id survives decoding" (Config.key_id c)
    (Config.key_id decoded)

let test_skipping () =
  let c = config () in
  let good = Config.encode c in
  let pk = Hpke.Public_key.to_bytes (Config.public_key c) in
  let future = versioned ~version:2 "anything at all" in
  let unknown_kem = versioned (u16 0x7777 ^ u16 1 ^ u16 1 ^ opaque16 pk) in
  let unknown_aead = versioned (u16 0x20 ^ u16 1 ^ u16 0x9999 ^ opaque16 pk) in
  let export_only = versioned (u16 0x20 ^ u16 1 ^ u16 0xffff ^ opaque16 pk) in
  let decoded =
    ok
      (Config.decode_list
         (list [ future; unknown_kem; good; unknown_aead; export_only ]))
  in
  Alcotest.(check int) "one supported" 1 (List.length decoded);
  Alcotest.(check (list (testable Config.pp Config.equal)))
    "all skipped" []
    (ok (Config.decode_list (list [ future; unknown_kem ])));
  check_error "unknown version alone" (Odoh.Error.Unsupported_version 2)
    (Config.decode future);
  check_error "unknown AEAD alone"
    (Odoh.Error.Unsupported_suite { kem = 0x20; kdf = 1; aead = 0x9999 })
    (Config.decode unknown_aead)

let invalid = function
  | Error (Odoh.Error.Invalid_config _) -> true
  | _ -> false

let test_malformed () =
  let c = config () in
  let good = Config.encode c in
  let pk = Hpke.Public_key.to_bytes (Config.public_key c) in
  let single r = Result.map (fun c -> [ c ]) r in
  let cases =
    [
      ("empty list", Config.decode_list (u16 0));
      ("nothing", Config.decode_list "");
      ("short list", Config.decode_list (String.sub (list [ good ]) 0 10));
      ("list trailing", Config.decode_list (list [ good ] ^ "\x00"));
      ( "config trailing inside list",
        Config.decode_list (list [ good ^ "\x00" ]) );
      ( "contents trailing",
        single (Config.decode (versioned (Config.encode_contents c ^ "x"))) );
      ( "short key",
        single
          (Config.decode
             (versioned
                (u16 0x20 ^ u16 1 ^ u16 1 ^ opaque16 (String.sub pk 0 31)))) );
      ( "empty key",
        single (Config.decode (versioned (u16 0x20 ^ u16 1 ^ u16 1 ^ u16 0))) );
      ( "invalid key in a list",
        Config.decode_list
          (list
             [
               good;
               versioned
                 (u16 0x10 ^ u16 1 ^ u16 1 ^ opaque16 (String.make 65 '\x04'));
             ]) );
      ( "truncated config",
        single (Config.decode (String.sub good 0 (String.length good - 1))) );
    ]
  in
  List.iter (fun (name, r) -> Alcotest.(check bool) name true (invalid r)) cases

let test_encode_list_misuse () =
  Alcotest.check_raises "empty"
    (Invalid_argument "Odoh.Config.encode_list: empty list") (fun () ->
      ignore (Config.encode_list []))

let tests =
  [
    Alcotest.test_case "create" `Quick test_create;
    Alcotest.test_case "layout" `Quick test_layout;
    Alcotest.test_case "skipping" `Quick test_skipping;
    Alcotest.test_case "malformed" `Quick test_malformed;
    Alcotest.test_case "encode_list misuse" `Quick test_encode_list_misuse;
  ]
  @ List.map
      (fun s ->
        Alcotest.test_case ("roundtrip " ^ suite_name s) `Quick (roundtrip s))
      (List.filter
         (fun (s : Odoh.Suite.t) -> s.aead = Hpke.Aead.Aes_128_gcm)
         all_suites)
