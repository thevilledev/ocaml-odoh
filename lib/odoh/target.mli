(** The target's side of an exchange (RFC 9230 Section 8).

    {[
      let* dns_query, context = Target.decrypt_query target query in
      (* Resolve [dns_query]. *)
      let* response = Target.encrypt_response ~rng context dns_response in
    ]} *)

module Key : sig
  type t
  (** An HPKE private key with the configuration that advertises it.

      RFC 9230 Section 5 recommends that a target rotate its keys every day. *)

  val generate :
    rng:Mirage_crypto_rng.g ->
    ?kdf:Hpke.Kdf.id ->
    ?aead:Hpke.Aead.id ->
    Hpke.Kem.id ->
    (t, Error.t) result
  (** [kdf] and [aead] default to those of {!Suite.default}. *)

  val derive :
    ?kdf:Hpke.Kdf.id ->
    ?aead:Hpke.Aead.id ->
    Hpke.Kem.id ->
    ikm:string ->
    (t, Error.t) result
  (** The key that RFC 9180 [DeriveKeyPair] derives from [ikm], which must be
      secret and hold at least as much entropy as a private key. odoh-go and
      odoh-rs derive the same key from the same input. *)

  val of_private_key :
    ?kdf:Hpke.Kdf.id -> ?aead:Hpke.Aead.id -> Hpke.Private_key.t -> t

  val config : t -> Config.t
end

type t
(** The keys that a target accepts queries for. *)

val create : Key.t list -> (t, Error.t) result
(** Returns {!Error.Invalid_config} if the list is empty, or if two keys have
    the same {!Config.key_id}: the same key and suite given twice. A rotation
    keeps the old key beside the new one until clients have fetched the new
    configuration. *)

val configs : t -> Config.t list
(** The configurations of the keys, in the order given to {!create}. *)

val encoded_configs : t -> string
(** The [ObliviousDoHConfigs] to publish: {!configs}, in that order of
    preference. *)

type context
(** What encrypts the response to one query. It holds the query and a secret
    exported from its HPKE context, and nothing of that context, so it is
    immutable. *)

val decrypt_query : t -> string -> (string * context, Error.t) result
(** [decrypt_query target query] is the DNS query that the [ObliviousDoHMessage]
    [query] carries, once its padding has been checked to be all zeros, and the
    context for its response.

    Returns {!Error.Unknown_key_id} for a key that the target does not hold,
    which RFC 9230 Section 8 answers with a 401, and
    {!Error.Unexpected_message_type} or {!Error.Malformed_message} for what is
    not a query. Every other failure is {!Error.Decryption_failed}, answered
    with a 400. {!Http_binding.Target.error_response} gives both answers. *)

val encrypt_response :
  rng:Mirage_crypto_rng.g ->
  ?padding:Message.Padding.t ->
  context ->
  string ->
  (string, Error.t) result
(** [encrypt_response ~rng context dns_response] is the [ObliviousDoHMessage] of
    type response that answers the query of [context]. It draws
    {!Suite.response_nonce_length} bytes from [rng] for the response nonce, and
    nothing else. [padding] defaults to {!Message.Padding.response}.

    A DNS response that reports a failure, such as SERVFAIL or NXDOMAIN, is
    still encrypted and sent with a 200 (RFC 9230 Section 4.3). *)
