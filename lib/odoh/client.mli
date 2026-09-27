(** The client's side of an exchange (RFC 9230 Section 7).

    {[
      let* query, context = Client.encrypt_query ~rng config dns_query in
      (* POST [query] to the proxy as application/oblivious-dns-message, and
         read the response that comes back. *)
      let* dns_response = Client.decrypt_response context response in
    ]}

    DNS messages are byte strings in the wire format of RFC 1035. This module
    does not parse them. *)

type context
(** What decrypts the response to one query. It holds the query and a secret
    exported from its HPKE context, and nothing of that context, so it is
    immutable. *)

val encrypt_query :
  rng:Mirage_crypto_rng.g ->
  ?padding:Message.Padding.t ->
  Config.t ->
  string ->
  (string * context, Error.t) result
(** [encrypt_query ~rng config dns_query] is an [ObliviousDoHMessage] of type
    query for the target that published [config], and the context for its
    response. Every call sets up a fresh HPKE context.

    [padding] defaults to {!Message.Padding.query}. Returns
    {!Error.Invalid_dns_message} if [dns_query] is empty or too long. *)

type sender_setup =
  Hpke.Suite.encryption Hpke.Suite.t ->
  recipient:Hpke.Public_key.t ->
  info:string ->
  (Hpke.Suite.encryption Hpke.Rfc9180.sender_setup, Hpke.Error.t) result
(** How the HPKE sender context is established. {!encrypt_query} uses
    [Hpke.Rfc9180.setup_base_sender ~rng]. *)

val encrypt_query_with :
  setup:sender_setup ->
  ?padding:Message.Padding.t ->
  Config.t ->
  string ->
  (string * context, Error.t) result
(** As {!encrypt_query}, with the HPKE sender context set up by [setup]. Only
    the [hpke] package can build a sender context, so [setup] cannot weaken the
    exchange unless it comes from [hpke.for_testing], whose deterministic
    senders reproduce test vectors. *)

val decrypt_response : context -> string -> (string, Error.t) result
(** [decrypt_response context response] is the DNS response carried by the
    [ObliviousDoHMessage] [response], after checking that its padding is all
    zeros. Returns {!Error.Decryption_failed} if it is not the target's answer
    to the query that produced [context], and {!Error.Unexpected_message_type}
    or {!Error.Malformed_message} if it is not a response at all. *)
