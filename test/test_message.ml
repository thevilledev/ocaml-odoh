(* Messages, plaintexts, and padding (RFC 9230 Section 6.1). *)

open Vectors
module Message = Odoh.Message
module Padding = Odoh.Message.Padding
module Plaintext = Odoh.Message.Plaintext

let test_message_layout () =
  let m =
    { Message.message_type = Query; key_id = "ab"; encrypted_message = "xyz" }
  in
  check_bytes "query" "\x01\x00\x02ab\x00\x03xyz" (Message.encode m);
  let r = { m with message_type = Response; key_id = "" } in
  check_bytes "response" "\x02\x00\x00\x00\x03xyz" (Message.encode r);
  Alcotest.(check bool)
    "roundtrip" true
    (Message.decode (Message.encode m) = Ok m)

let test_message_malformed () =
  let bad name expected s = check_error name expected (Message.decode s) in
  let malformed = function
    | Error (Odoh.Error.Malformed_message _) -> true
    | _ -> false
  in
  List.iter
    (fun (name, s) ->
      Alcotest.(check bool) name true (malformed (Message.decode s)))
    [
      ("empty", "");
      ("type only", "\x01");
      ("short key id", "\x01\x00\x05ab");
      ("no message", "\x01\x00\x00");
      ("empty message", "\x01\x00\x00\x00\x00");
      ("trailing", "\x01\x00\x00\x00\x01x!");
    ];
  bad "unknown type" (Odoh.Error.Unexpected_message_type 3)
    "\x03\x00\x00\x00\x01x";
  bad "type zero" (Odoh.Error.Unexpected_message_type 0) "\x00\x00\x00\x00\x01x"

let test_plaintext () =
  let p = ok (Plaintext.make ~padding:(Padding.fixed 3) "dns") in
  check_bytes "layout" "\x00\x03dns\x00\x03\x00\x00\x00" (Plaintext.encode p);
  Alcotest.(check bool)
    "roundtrip" true
    (Plaintext.decode (Plaintext.encode p) = Ok p);
  check_error "empty DNS message" (Odoh.Error.Invalid_dns_message "empty")
    (Plaintext.make "");
  check_error "long DNS message" (Odoh.Error.Invalid_dns_message "too long")
    (Plaintext.make (String.make 65536 'x'));
  List.iter
    (fun (name, s) ->
      check_error name Odoh.Error.Decryption_failed (Plaintext.decode s))
    [
      ("nonzero padding", "\x00\x03dns\x00\x02\x00\x01");
      ("empty DNS message", "\x00\x00\x00\x00");
      ("trailing", "\x00\x03dns\x00\x00x");
      ("truncated", "\x00\x03dn");
      ("no padding length", "\x00\x03dns");
    ]

let test_padding () =
  let len p n = Padding.length p n in
  Alcotest.(check int) "none" 0 (len Padding.none 50);
  Alcotest.(check int) "fixed" 7 (len (Padding.fixed 7) 50);
  Alcotest.(check int) "query block" (128 - 54) (len Padding.query 50);
  Alcotest.(check int) "exact block" 0 (len Padding.query 124);
  Alcotest.(check int) "response block" (468 - 104) (len Padding.response 100);
  List.iter
    (fun n ->
      let p = ok (Plaintext.make ~padding:Padding.query (String.make n 'q')) in
      Alcotest.(check int)
        (Printf.sprintf "multiple of 128 for %d" n)
        0
        (String.length (Plaintext.encode p) mod 128))
    [ 1; 17; 123; 124; 125; 300; 4000 ];
  Alcotest.check_raises "block 0"
    (Invalid_argument "Odoh.Message.Padding.block") (fun () ->
      ignore (Padding.block 0))

let tests =
  [
    Alcotest.test_case "message layout" `Quick test_message_layout;
    Alcotest.test_case "malformed messages" `Quick test_message_malformed;
    Alcotest.test_case "plaintext" `Quick test_plaintext;
    Alcotest.test_case "padding" `Quick test_padding;
  ]
