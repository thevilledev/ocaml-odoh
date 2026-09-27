(* Differential testing of odoh against other implementations of RFC 9230.

   Each peer is a program that speaks the line protocol of go/main.go. For every
   suite that a peer provides, the driver runs exchanges in both roles:

   - the OCaml client queries the peer as target, with a deterministic HPKE
   sender so that the query can be rebuilt later, and opens its response; - the
   peer queries the OCaml target, which answers with a chosen response nonce,
   and the peer opens that response.

   Every disagreement is reported, and the exit status is 1 if there was one.
   With --record DIR, each peer's exchanges are written to DIR/NAME.json, which
   test/test_differential.ml replays without the peer.

   differential.exe --peer NAME=COMMAND [--peer ...] [--record DIR] *)

open Odoh_test_support
module J = Yojson.Safe

let ( let* ) = Result.bind

module Peer = struct
  type t = { name : string; input : in_channel; output : out_channel }

  let start name command =
    let input, output = Unix.open_process_args command [| command |] in
    { name; input; output }

  let call t fields =
    output_string t.output (J.to_string (`Assoc fields));
    output_char t.output '\n';
    flush t.output;
    let answer = J.from_string (input_line t.input) in
    let open J.Util in
    if to_bool (member "ok" answer) then Ok answer
    else Error (to_string (member "error" answer))

  let stop t = ignore (Unix.close_process (t.input, t.output))
end

let hex s = `String (Hex.encode s)

let field answer name =
  Hex.decode (J.Util.to_string (J.Util.member name answer))

let failures = ref 0

let fail peer suite what =
  incr failures;
  Format.printf "FAIL %s, %a: %s@." peer.Peer.name Odoh.Suite.pp suite what

let get = function Ok v -> v | Error e -> failwith (Odoh.Error.to_string e)

let suite_fields (suite : Odoh.Suite.t) =
  let kem, kdf, aead = Odoh.Suite.to_ints suite in
  [ ("kem", `Int kem); ("kdf", `Int kdf); ("aead", `Int aead) ]

let paddings = [ (0, 0); (7, 64); (100, 468) ]

let key (suite : Odoh.Suite.t) n =
  get
    (Odoh.Target.Key.derive ~kdf:suite.kdf ~aead:suite.aead suite.kem
       ~ikm:(Fixtures.target_seed n))

(* The OCaml client, and the peer as target. *)
let client_case peer suite n (query_padding, response_padding) =
  let key = key suite n in
  let target = get (Odoh.Target.create [ key ]) in
  let config = Odoh.Target.Key.config key in
  let setup = get (Fixtures.deterministic_setup suite n) in
  let query, context =
    get
      (Odoh.Client.encrypt_query_with ~setup
         ~padding:(Odoh.Message.Padding.fixed query_padding)
         config Fixtures.dns_query)
  in
  let request =
    suite_fields suite
    @ [
        ("op", `String "target");
        ("seed", hex (Fixtures.target_seed n));
        ("query", hex query);
        ("response", hex Fixtures.dns_response);
        ("response_padding", `Int response_padding);
      ]
  in
  match Peer.call peer request with
  | Error e ->
      fail peer suite ("target refused the query: " ^ e);
      None
  | Ok answer ->
      let check what expected actual =
        if not (String.equal expected actual) then
          fail peer suite (what ^ " differs")
      in
      check "configuration"
        (Odoh.Target.encoded_configs target)
        (field answer "configs");
      check "key id" (Odoh.Config.key_id config) (field answer "key_id");
      check "decrypted query" Fixtures.dns_query (field answer "query");
      if J.Util.(to_int (member "query_padding" answer)) <> query_padding then
        fail peer suite "query padding differs";
      let response = field answer "response" in
      (match Odoh.Client.decrypt_response context response with
      | Ok dns -> check "response" Fixtures.dns_response dns
      | Error e -> fail peer suite ("response: " ^ Odoh.Error.to_string e));
      Some
        (`Assoc
           (suite_fields suite
           @ [
               ("case", `Int n);
               ("query_padding", `Int query_padding);
               ("response_padding", `Int response_padding);
               ("query", hex query);
               ("response", hex response);
             ]))

(* The peer as client, and the OCaml target. *)
let target_case peer suite n (query_padding, response_padding) =
  let target = get (Odoh.Target.create [ key suite n ]) in
  let request =
    [
      ("op", `String "query");
      ("handle", `Int n);
      ("configs", hex (Odoh.Target.encoded_configs target));
      ("query", hex Fixtures.dns_query);
      ("padding", `Int query_padding);
    ]
  in
  let* answer = Peer.call peer request in
  let query = field answer "query" in
  match Odoh.Target.decrypt_query target query with
  | Error e -> Error ("OCaml target: " ^ Odoh.Error.to_string e)
  | Ok (dns, context) ->
      if not (String.equal dns Fixtures.dns_query) then
        fail peer suite "query as the OCaml target read it";
      let nonce =
        Fixtures.response_nonce (Odoh.Suite.response_nonce_length suite) n
      in
      let response =
        get
          (Odoh.Target.encrypt_response
             ~rng:(Fixed_rng.of_string nonce)
             ~padding:(Odoh.Message.Padding.fixed response_padding)
             context Fixtures.dns_response)
      in
      let* answer =
        Peer.call peer
          [
            ("op", `String "open");
            ("handle", `Int n);
            ("response", hex response);
          ]
      in
      if not (String.equal (field answer "response") Fixtures.dns_response) then
        fail peer suite "response as the peer read it";
      Ok
        (`Assoc
           (suite_fields suite
           @ [
               ("case", `Int n);
               ("query_padding", `Int query_padding);
               ("response_padding", `Int response_padding);
               ("query", hex query);
               ("nonce", hex nonce);
               ("response", hex response);
             ]))

(* What each peer provides: odoh-rs only the mandatory suite, and odoh-go the
   Diffie-Hellman KEMs that its configuration parser knows, which leave out
   P-384. *)
let suites = function
  | "rust" -> [ Odoh.Suite.default ]
  | _ ->
      List.concat_map
        (fun kem ->
          List.concat_map
            (fun kdf ->
              List.map
                (fun aead -> { Odoh.Suite.kem; kdf; aead })
                Hpke.Aead.[ Aes_128_gcm; Aes_256_gcm; Chacha20_poly1305 ])
            Hpke.Kdf.[ Hkdf_sha256; Hkdf_sha384; Hkdf_sha512 ])
        Hpke.Kem.[ X25519; X448; P256; P521 ]

let run_peer ~record (name, command) =
  let peer = Peer.start name command in
  let hello =
    match Peer.call peer [ ("op", `String "hello") ] with
    | Ok h -> h
    | Error e -> failwith (name ^ ": " ^ e)
  in
  let n = ref 0 in
  let client = ref [] and target = ref [] in
  List.iter
    (fun suite ->
      List.iter
        (fun paddings ->
          incr n;
          Option.iter
            (fun c -> client := c :: !client)
            (client_case peer suite !n paddings);
          match target_case peer suite !n paddings with
          | Ok c -> target := c :: !target
          | Error e -> fail peer suite e)
        paddings)
    (suites name);
  Peer.stop peer;
  Format.printf "%s: %d suites, %d exchanges in each role@." name
    (List.length (suites name))
    !n;
  Option.iter
    (fun dir ->
      let doc =
        `Assoc
          [
            ("peer", `Assoc (List.remove_assoc "ok" (J.Util.to_assoc hello)));
            ("client", `List (List.rev !client));
            ("target", `List (List.rev !target));
          ]
      in
      let path = Filename.concat dir (name ^ ".json") in
      let oc = open_out path in
      J.pretty_to_channel oc doc;
      output_char oc '\n';
      close_out oc;
      Format.printf "recorded %s@." path)
    record

let () =
  let peers = ref [] and record = ref None in
  Arg.parse
    [
      ( "--peer",
        Arg.String
          (fun s ->
            match String.index_opt s '=' with
            | Some i ->
                peers :=
                  ( String.sub s 0 i,
                    String.sub s (i + 1) (String.length s - i - 1) )
                  :: !peers
            | None -> raise (Arg.Bad "--peer NAME=COMMAND")),
        "NAME=COMMAND  a peer to test against" );
      ( "--record",
        Arg.String (fun d -> record := Some d),
        "DIR  record the exchanges" );
    ]
    (fun a -> raise (Arg.Bad a))
    "differential.exe --peer NAME=COMMAND [--record DIR]";
  List.iter (run_peer ~record:!record) (List.rev !peers);
  if !failures > 0 then (
    Format.printf "%d disagreements@." !failures;
    exit 1)
