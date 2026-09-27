(* Crowbar fuzzing of everything in Oblivious DoH that reads a peer's bytes:
   configurations, messages, plaintexts, queries at a target, responses at a
   client, and requests at a proxy. None of it may raise, and a configuration or
   a message that decodes must encode to the bytes it came from. Build with
   [dune build --profile fuzz fuzz/fuzz_odoh.exe]. *)

open Crowbar

let get = function Ok v -> v | Error e -> failwith (Odoh.Error.to_string e)

let hex s =
  String.concat ""
    (List.init (String.length s) (fun i ->
         Printf.sprintf "%02x" (Char.code s.[i])))

let pp_hex fmt s = Format.pp_print_string fmt (hex s)

let total name f input =
  match f input with
  | Ok _ | Error _ -> ()
  | exception e ->
      fail (Printf.sprintf "%s raised %s" name (Printexc.to_string e))

let rng =
  Mirage_crypto_rng.create ~seed:(String.make 64 '\x5a')
    (module Mirage_crypto_rng.Fortuna)

let keys =
  List.map
    (fun kem -> get (Odoh.Target.Key.derive kem ~ikm:(String.make 66 '\x33')))
    Hpke.Kem.[ X25519; P256; Mlkem768; Mlkem768_x25519 ]

let target = get (Odoh.Target.create keys)

let contexts =
  List.map
    (fun key ->
      snd
        (get
           (Odoh.Client.encrypt_query ~rng (Odoh.Target.Key.config key) "query")))
    keys

let template =
  get (Odoh.Proxy.Template.parse "https://p.example/q{?targethost,targetpath}")

let path_template =
  get (Odoh.Proxy.Template.parse "https://p.example/{targethost}/{+targetpath}")

let reencodes name decode encode input =
  match decode input with
  | Error _ -> ()
  | Ok v -> check_eq ~pp:pp_hex ~eq:String.equal input (encode v)
  | exception e ->
      fail (Printf.sprintf "%s raised %s" name (Printexc.to_string e))

(* A query with some bytes of an honest one replaced, so that the fuzzer gets
   past the framing and the key identifier. *)
let honest_query =
  fst
    (get
       (Odoh.Client.encrypt_query ~rng
          (Odoh.Target.Key.config (List.hd keys))
          "query"))

let splice offset patch =
  let n = String.length honest_query in
  let offset = offset mod n in
  let patch = String.sub patch 0 (min (String.length patch) (n - offset)) in
  String.sub honest_query 0 offset
  ^ patch
  ^ String.sub honest_query
      (offset + String.length patch)
      (n - offset - String.length patch)

let () =
  add_test ~name:"Config.decode" [ bytes ]
    (reencodes "Config.decode" Odoh.Config.decode Odoh.Config.encode);
  add_test ~name:"Config.decode_contents" [ bytes ]
    (reencodes "Config.decode_contents" Odoh.Config.decode_contents
       Odoh.Config.encode_contents);
  add_test ~name:"Config.decode_list" [ bytes ]
    (total "Config.decode_list" Odoh.Config.decode_list);
  add_test ~name:"Message.decode" [ bytes ]
    (reencodes "Message.decode" Odoh.Message.decode Odoh.Message.encode);
  add_test ~name:"Plaintext.decode" [ bytes ]
    (reencodes "Plaintext.decode" Odoh.Message.Plaintext.decode
       Odoh.Message.Plaintext.encode);
  add_test ~name:"Target.decrypt_query" [ bytes ]
    (total "Target.decrypt_query" (Odoh.Target.decrypt_query target));
  add_test ~name:"Target.decrypt_query of a spliced query" [ int; bytes ]
    (fun offset patch ->
      let q = splice (abs offset) patch in
      match Odoh.Target.decrypt_query target q with
      | Ok _ -> check_eq ~pp:pp_hex ~eq:String.equal honest_query q
      | Error _ -> ()
      | exception e -> fail (Printexc.to_string e));
  add_test ~name:"Client.decrypt_response" [ bytes ] (fun input ->
      List.iter
        (fun c ->
          total "Client.decrypt_response" (Odoh.Client.decrypt_response c) input)
        contexts);
  add_test ~name:"Proxy.Template.parse" [ bytes ]
    (total "Proxy.Template.parse" Odoh.Proxy.Template.parse);
  add_test ~name:"Proxy.target_of_request" [ bytes ] (fun input ->
      total "Proxy.target_of_request"
        (Odoh.Proxy.target_of_request template)
        input;
      total "Proxy.target_of_request"
        (Odoh.Proxy.target_of_request path_template)
        input)
