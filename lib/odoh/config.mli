(** Target configurations (RFC 9230 Section 5).

    A configuration tells a client how to encrypt queries for a target: an HPKE
    suite and the target's public key. There are three encodings, one inside the
    other:

    - {!encode_contents} and {!decode_contents} handle
      [ObliviousDoHConfigContents], the suite and the key, from which the key
      identifier is computed;
    - {!encode} and {!decode} handle [ObliviousDoHConfig], the contents behind a
      version and a length;
    - {!encode_list} and {!decode_list} handle [ObliviousDoHConfigs], a list of
      versioned configurations behind a length, in decreasing order of
      preference. This is what a target publishes, in an [odohconfig] SvcParam
      or otherwise: RFC 9230 leaves distribution out of scope. *)

type t

val version : int
(** [0x0001], the version of Oblivious DoH that RFC 9230 specifies. *)

val create : ?kdf:Hpke.Kdf.id -> ?aead:Hpke.Aead.id -> Hpke.Public_key.t -> t
(** [create public_key] describes [public_key] with the KEM of the key and [kdf]
    and [aead], which default to those of {!Suite.default}. *)

val suite : t -> Suite.t
val public_key : t -> Hpke.Public_key.t

val key_id : t -> string
(** [Expand(Extract("", contents), "odoh key id", Nh)] with the configuration's
    KDF, over the encoded contents: the identifier by which a query names the
    key (RFC 9230 Section 6.1). *)

val encode_contents : t -> string
(** [ObliviousDoHConfigContents]. *)

val decode_contents : string -> (t, Error.t) result
(** [ObliviousDoHConfigContents]. Returns {!Error.Unsupported_suite} for an
    algorithm that this library does not provide, and {!Error.Invalid_config}
    for anything malformed, a public key that is not valid for its KEM and
    trailing bytes included. *)

val encode : t -> string
(** [ObliviousDoHConfig], of version {!version}. *)

val decode : string -> (t, Error.t) result
(** [ObliviousDoHConfig]. Returns {!Error.Unsupported_version} for a version
    other than {!version}, and otherwise fails as {!decode_contents}. *)

val encode_list : t list -> string
(** [ObliviousDoHConfigs].

    Raises [Invalid_argument] if the list is empty or longer than the 65535
    bytes that the encoding can hold. *)

val decode_list : string -> (t list, Error.t) result
(** [ObliviousDoHConfigs], in the order of the list. As RFC 9230 Section 5
    requires, a configuration of another version, or with an algorithm that this
    library does not provide, is skipped; the result can be empty when every one
    was. Anything malformed rejects the whole list, a configuration of a known
    version and suite with an invalid public key included, and so does an empty
    list, which the encoding does not allow. *)

val equal : t -> t -> bool
val pp : Format.formatter -> t -> unit
