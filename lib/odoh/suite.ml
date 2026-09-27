type t = { kem : Hpke.Kem.id; kdf : Hpke.Kdf.id; aead : Hpke.Aead.id }

let default =
  {
    kem = Hpke.Kem.X25519;
    kdf = Hpke.Kdf.Hkdf_sha256;
    aead = Hpke.Aead.Aes_128_gcm;
  }

let of_ints ~kem ~kdf ~aead =
  match (Hpke.Kem.of_int kem, Hpke.Kdf.of_int kdf, Hpke.Aead.of_int aead) with
  | Ok kem, Ok kdf, Ok aead -> Ok { kem; kdf; aead }
  | _ -> Error (Error.Unsupported_suite { kem; kdf; aead })

let to_ints t =
  (Hpke.Kem.to_int t.kem, Hpke.Kdf.to_int t.kdf, Hpke.Aead.to_int t.aead)

let hpke t = Hpke.Suite.create ~kem:t.kem ~kdf:t.kdf ~aead:t.aead

let response_nonce_length t =
  max (Hpke.Aead.nonce_size t.aead) (Hpke.Aead.key_size t.aead)

let equal a b = a.kem = b.kem && a.kdf = b.kdf && a.aead = b.aead

let pp fmt t =
  Format.fprintf fmt "%a, %a, %a" Hpke.Kem.pp t.kem Hpke.Kdf.pp t.kdf
    Hpke.Aead.pp t.aead
