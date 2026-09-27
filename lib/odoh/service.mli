(** The client, proxy, and target of RFC 9230 Section 4, as steps from HTTP
    messages to HTTP messages.

    Nothing here performs I/O. Each party is a function from what it received to
    what it sends, and the HTTP library in between does the sending: this is
    what the adapter package [odoh-cohttp-lwt] wraps, and what an adapter for
    another library wraps too.

    A message is its status, where it has one, its fields, and its content. The
    fields are pairs of a lowercase name and a value, and the content is read in
    full. *)

type request = { headers : (string * string) list; body : string }
(** A request to send: the method is always [POST], and the URI is given with
    each step. *)

type response = Http_binding.error_response = {
  status : int;
  headers : (string * string) list;
  body : string;
}

val well_known_configs_path : string
(** ["/.well-known/odohconfigs"], where a target serves its
    [ObliviousDoHConfigs] to a [GET]. RFC 9230 leaves the distribution of
    configurations out of scope; this is the path that odoh-server-go,
    doh-server, and the [q] client use. A client that fetches its configurations
    from the target directly reveals its address to the target, once. *)

(** {1 Limits}

    A proxy and a target read each message in full before they act on it, so
    what they hold at once grows with the length of each message and with the
    number of requests that they handle together. Both are bounded, by default
    with these values, and the adapters refuse what exceeds them without keeping
    it. *)

val default_max_message_size : int
(** The longest message that a client, proxy, or target reads:
    {!Http_binding.max_message_length}, the longest that the encoding allows,
    about 128 KiB. *)

val default_max_in_flight : int
(** How many requests a proxy or a target handles at once: 256. *)

val exceeds : max_size:int -> (string * string) list -> bool
(** [exceeds ~max_size headers] is whether the [content-length] field in
    [headers] declares more than [max_size] bytes, so that the content can be
    refused before it is read. A message without the field can still be too
    long: its content must be counted as it is read. *)

val content_too_large : response
(** The answer to a request that is longer than a proxy or a target accepts: a
    413. *)

val busy : response
(** The answer to a request that arrives while a proxy or a target handles as
    many as it accepts: a 503, with [retry-after: 1]. *)

val not_found : response
(** A 404, for a path that serves nothing. *)

(** A counter of requests in flight, safe to use from several domains. *)
module Admission : sig
  type t

  val create : max_in_flight:int -> t
  (** Raises [Invalid_argument] unless [max_in_flight] is positive. *)

  val admit : t -> bool
  (** [admit t] counts one more request in flight, and is [true], unless
      [max_in_flight] are in flight already: then it is [false], and the request
      is to be answered with {!busy}. Each [true] must be followed by one
      {!release} once the request has been answered. *)

  val release : t -> unit
end

(** A client: sends a query through a proxy, and opens the response that comes
    back. *)
module Client : sig
  val configs :
    status:int ->
    headers:(string * string) list ->
    string ->
    (Config.t list, Error.t) result
  (** The configurations in the answer to a [GET] of {!well_known_configs_path}:
      those of the list that this library supports, in order of preference. A
      status other than a 2xx is {!Error.Unexpected_status}.

      Configurations must be obtained in a way that authenticates the target,
      and the same ones must be given to every client, or the target can tell
      clients apart: that is up to the application. *)

  type exchange
  (** A query that has been sent, and what is needed to open its response. *)

  val start :
    rng:Mirage_crypto_rng.g ->
    ?padding:Message.Padding.t ->
    Config.t ->
    string ->
    (request * exchange, Error.t) result
  (** [start ~rng config dns_query] is the [POST] to send to the proxy's URI for
      the target of [config] ({!Proxy.Template.expand}), and the exchange that
      opens its response. See {!Client.encrypt_query}. *)

  val finish :
    exchange ->
    status:int ->
    headers:(string * string) list ->
    string ->
    (string, Error.t) result
  (** The DNS response in the proxy's answer. An answer that is not a 2xx of
      type [application/oblivious-dns-message] is an error (see
      {!Http_binding.Client.check_response}): a 401 means that the configuration
      is out of date. *)
end

(** A proxy: forwards each query to the target that its request names, and the
    answer back, and nothing that identifies the client (RFC 9230 Sections 4.1,
    4.3, and 4.5). It cannot read what it carries. *)
module Proxy : sig
  type t

  type route = Proxy.target -> string option
  (** Where a proxy sends queries for a target: the URI to [POST] them to, or
      [None] to refuse the target with a 403. This is the proxy's policy
      (Section 11.2). A proxy that forwarded to any target that its clients
      named would let them reach any HTTPS server that the proxy can, internal
      ones included. *)

  val allow : ?ports:int list -> string list -> route
  (** [allow hosts] routes a target whose host is one of [hosts], compared
      without regard to case, to {!Odoh.Proxy.target_uri}, when it has no port
      or one of [ports] (only 443 by default), and refuses every other. *)

  val create :
    ?name:string ->
    ?max_message_size:int ->
    ?max_in_flight:int ->
    template:Proxy.Template.t ->
    route:route ->
    unit ->
    t
  (** A proxy that reads the targets from requests with [template], and sends
      them where [route] says. It names itself [name] in [proxy-status] fields,
      ["odoh-proxy"] by default. It reads queries and answers of at most
      [max_message_size] bytes, {!default_max_message_size} by default, and
      handles at most [max_in_flight] requests at once, {!default_max_in_flight}
      by default. Raises [Invalid_argument] unless both are positive.

      One proxy is meant to serve every request: the requests in flight are
      counted in it. *)

  val name : t -> string
  val max_message_size : t -> int
  val admission : t -> Admission.t

  val request :
    t ->
    meth:string ->
    headers:(string * string) list ->
    target:string ->
    string ->
    (string * request, response) result
  (** [request proxy ~meth ~headers ~target body] is the URI to [POST] to and
      the request to send, for a client's request with the request target
      [target] (its path and query) and content [body]. For anything that is not
      a [POST] of type [application/oblivious-dns-message] naming a valid
      target, the answer to give the client instead: a 400, 405, or 415 of error
      type [http_request_error], or a 403 of type [http_request_denied] for a
      target that [route] refuses. *)

  val response :
    t -> status:int -> headers:(string * string) list -> string -> response
  (** The answer to give the client for the target's: its status and content
      unchanged, with the fields of {!Odoh.Proxy.response_headers}. An answer
      longer than [max_message_size] is a 502 instead, of error type
      [http_response_body_size]. *)

  val unreachable : t -> ?error:string -> unit -> response
  (** The answer to give the client when the target cannot be reached: a 502 of
      error type [error], ["destination_unavailable"] by default. *)
end

(** A target: serves its configurations, and answers each query with an
    encrypted response. *)
module Target : sig
  type t

  val create :
    rng:Mirage_crypto_rng.g ->
    ?padding:Message.Padding.t ->
    ?max_message_size:int ->
    ?max_in_flight:int ->
    Target.t ->
    t
  (** A target with the keys of a {!Odoh.Target.t}. [rng] draws the response
      nonces, and [padding] pads the responses as with
      {!Odoh.Target.encrypt_response}. It reads queries of at most
      [max_message_size] bytes and handles at most [max_in_flight] of them at
      once, with the defaults of {!Proxy.create}. *)

  val max_message_size : t -> int
  val admission : t -> Admission.t

  val configs : t -> response
  (** The answer to a [GET] of {!well_known_configs_path}: the
      [ObliviousDoHConfigs] of the target's keys. *)

  type step =
    | Respond of response  (** The answer to give, in the clear. *)
    | Resolve of string * (string -> response)
        (** The DNS query to resolve, and what encrypts its answer. The target
            gets a DNS response for the query, from a resolver or of its own
            making, and gives what the function returns for it. A query that
            cannot be resolved is answered with a DNS response too, such as
            {!servfail}, and with a 200 (Section 4.3). *)

  val receive :
    t -> meth:string -> headers:(string * string) list -> string -> step
  (** [receive target ~meth ~headers content] is the step for a request to the
      target's resource. A request that is not a [POST] of type
      [application/oblivious-dns-message], that is longer than
      [max_message_size], or whose query does not decrypt is answered in the
      clear, with {!Http_binding.Target.error_response}: a 401 for an unknown
      key, a 400 for a query that does not decrypt. *)
end

val servfail : string -> string
(** [servfail dns_query] is a DNS response with the RCODE SERVFAIL to a query in
    the wire format of RFC 1035: its header, with the QR and RA bits set, and
    its question, if it can be read, and nothing else. It is what a target
    answers when its resolver fails. A query too short for a header gets a
    header with an identifier of zero. *)
