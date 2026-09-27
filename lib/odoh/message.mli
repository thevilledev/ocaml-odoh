(** Oblivious DoH messages (RFC 9230 Section 6.1).

    An [ObliviousDoHMessage] is what travels over HTTP: a type, a key
    identifier, and an encrypted [ObliviousDoHMessagePlaintext], which holds a
    DNS message and zero padding. {!Client} and {!Target} build and read both;
    they are exposed for tools and for other implementations' tests. *)

type message_type = Query | Response

val message_type_to_int : message_type -> int

type t = {
  message_type : message_type;
  key_id : string;
      (** For a query, the {!Config.key_id} of the target's key; for a response,
          the response nonce. *)
  encrypted_message : string;
}

val encode : t -> string
(** Raises [Invalid_argument] if [key_id] or [encrypted_message] is longer than
    65535 bytes, or [encrypted_message] is empty. *)

val decode : string -> (t, Error.t) result
(** Returns {!Error.Unexpected_message_type} for a type other than a query or a
    response, and {!Error.Malformed_message} for a truncated message, one with
    trailing bytes, or one whose [encrypted_message] is empty. *)

module Padding : sig
  (** How much zero padding a plaintext carries. RFC 9230 leaves the choice to
      the implementation and points to the policies of RFC 8467, which pad a
      message to a multiple of a block length so that its length reveals less
      about its content. *)

  type t

  val none : t

  val block : int -> t
  (** [block n] pads the encoded plaintext to a multiple of [n] bytes.

      Raises [Invalid_argument] unless [n] is between 1 and 65535. *)

  val fixed : int -> t
  (** [fixed n] adds exactly [n] bytes.

      Raises [Invalid_argument] unless [n] is between 0 and 65535. *)

  val query : t
  (** [block 128], what RFC 8467 Section 4.1 recommends for queries. *)

  val response : t
  (** [block 468], what RFC 8467 Section 4.1 recommends for responses. *)

  val length : t -> int -> int
  (** [length policy dns_length] is the number of padding bytes for a DNS
      message of [dns_length] bytes. *)
end

module Plaintext : sig
  type t = private { dns_message : string; padding_length : int }
  (** An [ObliviousDoHMessagePlaintext]: a DNS message and the length of its
      padding, which is all zeros. *)

  val make : ?padding:Padding.t -> string -> (t, Error.t) result
  (** Returns {!Error.Invalid_dns_message} if the DNS message is empty, or if it
      and its padding do not fit in 65535 bytes each. [padding] defaults to
      {!Padding.none}. *)

  val encode : t -> string

  val decode : string -> (t, Error.t) result
  (** Returns {!Error.Decryption_failed} for anything but a non-empty DNS
      message and all-zero padding, with nothing after them: what a peer
      encrypted is not told apart from what did not decrypt. *)
end
