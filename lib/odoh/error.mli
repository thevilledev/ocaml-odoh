(** Errors returned by the public API. Messages describe classes of invalid
    input and never contain key material or message content. *)

type t =
  | Invalid_config of string
      (** A target configuration, or a list of them, is malformed. *)
  | Unsupported_version of int
      (** A configuration is for a version of Oblivious DoH other than [0x0001].
      *)
  | Unsupported_suite of { kem : int; kdf : int; aead : int }
      (** A configuration names an HPKE algorithm that this library does not
          provide. *)
  | Malformed_message of string
      (** An [ObliviousDoHMessage] is not well formed: it is truncated, has
          trailing bytes, or an empty [encrypted_message]. *)
  | Unexpected_message_type of int
      (** A message of another type than expected: a response where a query
          belongs, or the other way around, or an unknown type. *)
  | Invalid_dns_message of string
      (** A DNS message to be encrypted is empty, or too long to encrypt with
          the requested padding. *)
  | Unknown_key_id
      (** A query names a key that the target does not hold. RFC 9230 Section
          4.3 answers it with a 401. *)
  | Decryption_failed
      (** A query or a response did not decrypt, or what it decrypted to is not
          a well-formed [ObliviousDoHMessagePlaintext] with zero padding. Every
          failure of that kind is reported this way, so that a target does not
          tell its peer which step failed. *)
  | Content_too_large of int
      (** A message is longer than its reader accepts. The argument is the
          limit, in bytes. *)
  | Method_not_allowed of string  (** A request was not a [POST]. *)
  | Unsupported_media_type of string option
      (** A request does not carry [application/oblivious-dns-message]. *)
  | Unexpected_status of int
      (** A client was answered with a status other than a 2xx, and so not with
          an encrypted response. *)
  | Unexpected_content_type of string option
      (** A client was answered with content of another media type. *)
  | Invalid_template of string
      (** A proxy URI template does not conform to RFC 9230 Section 4.1. *)
  | Invalid_target of string
      (** A request to a proxy does not name a valid target through the
          template's [targethost] and [targetpath] variables. *)
  | Hpke of Hpke.Error.t  (** A failure that is not the peer's doing. *)

val to_string : t -> string
val pp : Format.formatter -> t -> unit
