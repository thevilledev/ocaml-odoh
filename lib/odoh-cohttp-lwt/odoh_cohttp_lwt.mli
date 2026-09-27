(** Oblivious DoH over cohttp-lwt.

    The client, proxy, and target of {!Odoh.Service}, as calls and server
    callbacks of cohttp-lwt. The client, the proxy, and the DoH resolver make
    requests of their own, with any client of cohttp-lwt: that of
    [cohttp-lwt-unix], or of [cohttp-lwt-jsoo], or of a MirageOS unikernel.

    {[
    module Odoh_client = Odoh_cohttp_lwt.Make (Cohttp_lwt_unix.Client)

    (* A target in front of a DoH resolver, over cohttp-lwt-unix. Build each
       handler once: the requests in flight are counted in [service]. *)
    let target =
      Odoh_cohttp_lwt.Target.handler service
        (Odoh_client.Resolver.doh
           (Uri.of_string "http://127.0.0.1:3000/dns-query"))

    let () =
      Lwt_main.run
        (Cohttp_lwt_unix.Server.create
           (Cohttp_lwt_unix.Server.make ~callback:(fun _conn -> target) ()))
    ]}

    RFC 9230 requires HTTPS between every two parties. These handlers serve
    plain HTTP, and are meant to be deployed behind something that terminates
    TLS, or with a cohttp-lwt server that does.

    Contents are read in full. Each read is limited (see
    {!Odoh.Service.default_max_message_size}): what is longer is refused as soon
    as its declared length or what has arrived of it passes the limit, and the
    rest of it is read without being kept, since cohttp-lwt frees a connection
    only once its body has been read. *)

type handler =
  Http.Request.t ->
  Cohttp_lwt.Body.t ->
  (Http.Response.t * Cohttp_lwt.Body.t) Lwt.t
(** The callback of a cohttp-lwt server, without its connection:
    [Cohttp_lwt_unix.Server.make ~callback:(fun _conn -> handler) ()]. *)

type resolve = string -> string Lwt.t
(** How a target answers a DNS query, both in the wire format of RFC 1035: with
    a resolver, with {!Make.Resolver.doh}, or in any other way. A resolver that
    fails should answer with {!Odoh.Service.servfail}; an exception is answered
    that way. *)

(** A target: its configurations, and the resource to which proxies send
    queries. *)
module Target : sig
  val handler : ?path:string -> Odoh.Service.Target.t -> resolve -> handler
  (** Serves {!configs} to a [GET] of {!Odoh.Service.well_known_configs_path},
      {!queries} at [path], ["/dns-query"] by default, and a 404 elsewhere. *)

  val configs : Odoh.Service.Target.t -> handler
  (** Answers with the configurations, whatever the request. *)

  val queries : Odoh.Service.Target.t -> resolve -> handler
  (** Answers a query with an encrypted response, through
      {!Odoh.Service.Target.receive}. A request longer than the
      [max_message_size] of [service] is answered with
      {!Odoh.Service.content_too_large}, and one that arrives while
      [max_in_flight] are being answered with {!Odoh.Service.busy}. *)
end

module Make (Http_client : Cohttp_lwt.S.Client) : sig
  (** A client: fetches configurations, and sends queries through a proxy. *)
  module Client : sig
    val configs :
      ?ctx:Http_client.ctx ->
      ?max_response_size:int ->
      Uri.t ->
      (Odoh.Config.t list, Odoh.Error.t) result Lwt.t
    (** Fetches the configurations at a URI, such as a target's
        {!Odoh.Service.well_known_configs_path}.

        This is a plain [GET], which reveals the client's address to whoever
        serves the configurations. A client must obtain configurations in a way
        that authenticates the target and gives every client the same ones. An
        answer longer than [max_response_size],
        {!Odoh.Service.default_max_message_size} by default, is
        [Content_too_large]. *)

    val query :
      ?ctx:Http_client.ctx ->
      ?max_response_size:int ->
      rng:Mirage_crypto_rng.g ->
      ?padding:Odoh.Message.Padding.t ->
      proxy:Uri.t ->
      Odoh.Config.t ->
      string ->
      (string, Odoh.Error.t) result Lwt.t
    (** [query ~rng ~proxy config dns_query] sends [dns_query] to the target of
        [config] through the proxy at [proxy], the proxy's URI template expanded
        for the target ({!Odoh.Proxy.Template.expand}), and gives the DNS
        response. An answer that the target did not encrypt is an error, and so
        is one longer than [max_response_size]. A failure to reach the proxy is
        the exception of [Http_client]. *)
  end

  (** A proxy, which forwards to the targets that its policy allows. *)
  module Proxy : sig
    val handler : ?ctx:Http_client.ctx -> Odoh.Service.Proxy.t -> handler
    (** Forwards every [POST] of a query to the target that its request target
        names through the proxy's template, and the target's answer back,
        through {!Odoh.Service.Proxy}. Nothing about the client goes to the
        target: not its address, and no field but the content type and [accept].
        A target that does not answer gives a 502.

        A request longer than the [max_message_size] of [proxy] is answered with
        {!Odoh.Service.content_too_large}, and one that arrives while
        [max_in_flight] are being forwarded with {!Odoh.Service.busy}.

        A proxy should reuse its connections to targets (RFC 9230 Section 11.2):
        that is up to [Http_client]. *)
  end

  (** Resolvers for a target. *)
  module Resolver : sig
    val doh : ?ctx:Http_client.ctx -> ?max_response_size:int -> Uri.t -> resolve
    (** [doh uri] resolves a query by posting it as [application/dns-message] to
        the DNS over HTTPS resolver at [uri] (RFC 8484). A resolver that fails,
        answers with anything other than a 200 of that type, or with more than
        [max_response_size] bytes, 65535 by default, gives a SERVFAIL. *)
  end
end
