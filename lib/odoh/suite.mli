(** HPKE ciphersuites as Oblivious DoH names them (RFC 9230 Sections 5 and 9).

    A target configuration names one KEM, one KDF, and one AEAD. Every KEM of
    the [hpke] package can be named, with the KDFs and AEADs of RFC 9180: the
    Diffie-Hellman KEMs, the post-quantum/traditional hybrids such as
    MLKEM768-X25519 (X-Wing), and ML-KEM. The one-stage SHAKE KDFs of
    [draft-ietf-hpke-pq] cannot be, since the key identifier and the response
    keys are derived with [Extract] and [Expand].

    The other implementations are narrower: odoh-rs provides only {!default},
    and odoh-go the Diffie-Hellman KEMs other than P-384. A post-quantum
    configuration is therefore one that only clients of this library can use,
    and a target that offers one should offer {!default} beside it. *)

type t = { kem : Hpke.Kem.id; kdf : Hpke.Kdf.id; aead : Hpke.Aead.id }

val default : t
(** DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and AES-128-GCM: the suite that RFC
    9230 Section 9 requires every implementation to support. *)

val of_ints : kem:int -> kdf:int -> aead:int -> (t, Error.t) result
(** Returns {!Error.Unsupported_suite} unless this library provides all three.
*)

val to_ints : t -> int * int * int
(** The KEM, KDF, and AEAD identifiers. *)

val hpke : t -> Hpke.Suite.encryption Hpke.Suite.t

val response_nonce_length : t -> int
(** [max(Nn, Nk)]: the length of the nonce that a target draws for each response
    (RFC 9230 Section 8). *)

val equal : t -> t -> bool
val pp : Format.formatter -> t -> unit
