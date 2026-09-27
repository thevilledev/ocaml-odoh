(* Target configurations (RFC 9230 Section 5). *)

type t = { suite : Suite.t; public_key : Hpke.Public_key.t; key_id : string }

let version = 0x0001
let label_key_id = "odoh key id"

let contents_of suite public_key =
  let kem, kdf, aead = Suite.to_ints suite in
  let b = Buffer.create 64 in
  Buffer.add_uint16_be b kem;
  Buffer.add_uint16_be b kdf;
  Buffer.add_uint16_be b aead;
  Wire.add_opaque16 b (Hpke.Public_key.to_bytes public_key);
  Buffer.contents b

(* Expand(Extract("", config), "odoh key id", Nh). The length is Nh, which
   [expand] always accepts. *)
let compute_key_id suite public_key =
  let kdf = suite.Suite.kdf in
  let prk = Hpke.Kdf.extract kdf ~salt:"" (contents_of suite public_key) in
  match
    Hpke.Kdf.expand kdf ~prk ~info:label_key_id (Hpke.Kdf.hash_size kdf)
  with
  | Ok key_id -> key_id
  | Error e -> invalid_arg (Format.asprintf "Odoh.Config: %a" Hpke.Error.pp e)

let make suite public_key =
  { suite; public_key; key_id = compute_key_id suite public_key }

let create ?(kdf = Suite.default.kdf) ?(aead = Suite.default.aead) public_key =
  make { Suite.kem = Hpke.Public_key.kem public_key; kdf; aead } public_key

let suite t = t.suite
let public_key t = t.public_key
let key_id t = t.key_id
let encode_contents t = contents_of t.suite t.public_key

let encode t =
  let contents = encode_contents t in
  Wire.u16_string version ^ Wire.opaque16_string contents

let ( let* ) = Result.bind

(* The algorithms and the key, which [decode_contents] reads from exactly the
   bytes it is given. *)
let read_contents c =
  let kem = Wire.u16 "KEM identifier" c in
  let kdf = Wire.u16 "KDF identifier" c in
  let aead = Wire.u16 "AEAD identifier" c in
  let public_key = Wire.opaque16 "public key" c in
  (kem, kdf, aead, public_key)

let decode_contents s =
  match Wire.run read_contents s with
  | Error msg -> Error (Error.Invalid_config msg)
  | Ok (kem, kdf, aead, public_key) -> (
      let* suite = Suite.of_ints ~kem ~kdf ~aead in
      match Hpke.Public_key.of_bytes ~kem:suite.kem public_key with
      | Ok public_key -> Ok (make suite public_key)
      | Error _ -> Error (Error.Invalid_config "invalid public key"))

let read_config c =
  let v = Wire.u16 "version" c in
  let contents = Wire.opaque16 "contents" c in
  (v, contents)

let decode s =
  match Wire.run read_config s with
  | Error msg -> Error (Error.Invalid_config msg)
  | Ok (v, _) when v <> version -> Error (Error.Unsupported_version v)
  | Ok (_, contents) -> decode_contents contents

let encode_list ts =
  if ts = [] then invalid_arg "Odoh.Config.encode_list: empty list";
  let configs = String.concat "" (List.map encode ts) in
  if String.length configs > Wire.max_u16 then
    invalid_arg "Odoh.Config.encode_list: list too long";
  Wire.opaque16_string configs

let decode_list s =
  let read_all c =
    let body = Wire.opaque16 "configurations" c in
    let c = { Wire.data = body; pos = 0 } in
    let rec loop acc =
      if Wire.at_end c then List.rev acc else loop (read_config c :: acc)
    in
    (String.length body, loop [])
  in
  match Wire.run read_all s with
  | Error msg -> Error (Error.Invalid_config msg)
  | Ok (0, _) -> Error (Error.Invalid_config "empty list")
  | Ok (_, configs) ->
      let rec keep acc = function
        | [] -> Ok (List.rev acc)
        | (v, _) :: rest when v <> version -> keep acc rest
        | (_, contents) :: rest -> (
            match decode_contents contents with
            | Ok t -> keep (t :: acc) rest
            | Error (Error.Unsupported_suite _) -> keep acc rest
            | Error _ as e -> e)
      in
      keep [] configs

let equal a b =
  Suite.equal a.suite b.suite
  && String.equal
       (Hpke.Public_key.to_bytes a.public_key)
       (Hpke.Public_key.to_bytes b.public_key)

let pp fmt t =
  Format.fprintf fmt "@[<hv 2>{ suite = %a;@ key_id = %s }@]" Suite.pp t.suite
    (String.concat ""
       (List.init (String.length t.key_id) (fun i ->
            Printf.sprintf "%02x" (Char.code t.key_id.[i]))))
