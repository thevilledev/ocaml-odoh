(* What the client and the target share: the labels, the additional data, and
   the derivation of the response key and nonce (RFC 9230 Section 6.2). *)

let label_query = "odoh query"
let label_response = "odoh response"
let label_key = "odoh key"
let label_nonce = "odoh nonce"
let query_aad key_id = "\x01" ^ Wire.opaque16_string key_id
let response_aad nonce = "\x02" ^ Wire.opaque16_string nonce
let hpke r = Result.map_error (fun e -> Error.Hpke e) r
let ( let* ) = Result.bind

type secret = { suite : Suite.t; query : string; secret : string }
(* [query] is the encoded ObliviousDoHMessagePlaintext of the query, and
   [secret] what the HPKE context exported for the response, Nk bytes. *)

let secret_length suite = Hpke.Aead.key_size suite.Suite.aead

(* derive_secrets: the salt is Q_plain || len(resp_nonce) || resp_nonce. *)
let derive t response_nonce =
  let kdf = t.suite.kdf and aead = t.suite.aead in
  let salt = t.query ^ Wire.opaque16_string response_nonce in
  let prk = Hpke.Kdf.extract kdf ~salt t.secret in
  hpke
    (let* key =
       Hpke.Kdf.expand kdf ~prk ~info:label_key (Hpke.Aead.key_size aead)
     in
     let* nonce =
       Hpke.Kdf.expand kdf ~prk ~info:label_nonce (Hpke.Aead.nonce_size aead)
     in
     let* key = Hpke.Aead.key aead key in
     Ok (key, nonce))
