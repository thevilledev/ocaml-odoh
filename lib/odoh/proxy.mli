(** The proxy's side of an exchange (RFC 9230 Sections 4.1, 4.3, and 4.5).

    A proxy forwards queries without cryptography: it learns who the client is
    and which target it asks, and nothing of the query. What it must get right
    is what it forwards. This module reads the target from the request through
    the proxy's URI template, and gives the fields to send on either side, so
    that nothing that identifies the client reaches the target.

    {[
      let* () = Proxy.check_request ~meth ~headers in
      let* target = Proxy.target_of_request template request_target in
      (* Apply the proxy's policy to [target], then POST the body unchanged to
         [Proxy.target_uri target] with [Proxy.target_request_headers], and
         answer with the target's status and body, and with
         [Proxy.response_headers ~name ~status ~headers]. *)
    ]}

    Which targets to forward to is the proxy's policy (Section 11.2). It may
    refuse non-standard ports with a 403 ({!denied}). It should pool and reuse
    its connections to targets, so that a target cannot tell clients apart by
    connection. *)

module Template : sig
  (** Proxy URI templates: RFC 6570 URI templates with the [targethost] and
      [targetpath] variables, such as
      ["https://dnsproxy.example/dns-query{?targethost,targetpath}"] or
      ["https://dnsproxy.example/{targethost}/{targetpath}"].

      A template must use the [https] scheme, contain each of the two variables
      exactly once and no other, and have them in the path or the query (Section
      4.1). Expressions use the operators of Level 3 other than fragment and
      label expansion: simple, [+], [/], [;], [?], and [&]. Clients must ignore
      configurations with a template that does not conform. *)

  type t

  val parse : string -> (t, Error.t) result
  (** Returns {!Error.Invalid_template} for a template that does not conform, or
      that this library cannot match requests against: one with two adjacent
      expressions where the second starts with no delimiter. A reserved
      [{+targetpath}] starts with the ["/"] of the path, so
      ["https://dnsproxy.example/{+targethost}{+targetpath}"] is accepted. *)

  val to_string : t -> string

  val expand : t -> targethost:string -> targetpath:string -> string
  (** The URI to which a client posts its queries for the target at
      [https://targethost/targetpath] (RFC 6570 Section 3). For example,
      ["https://dnsproxy.example/dns-query?targethost=dnstarget.example&targetpath=%2Fdns-query"].
  *)
end

type target = { host : string; port : int option; path : string }
(** A target as a request names it: [host] is a lowercase DNS name, an IPv4
    address, or a bracketed IPv6 address, and [path] an absolute path. *)

val target_of_request : Template.t -> string -> (target, Error.t) result
(** [target_of_request template request_target] is the target named by a request
    with the path and query [request_target], such as
    ["/dns-query?targethost=dnstarget.example&targetpath=/dns-query"]: the value
    of [targethost] as the host, and the percent-decoded value of [targetpath]
    as the path (Section 4.1).

    The request target must be what expanding [template] would produce, but for
    the order of [?] and [&] parameters, which is free, and for percent
    encoding: [targetpath=/dns-query], as the example of Section 4.2 writes it,
    is accepted beside [targetpath=%2Fdns-query]. Returns
    {!Error.Invalid_target} otherwise, and for a host or path that is not valid,
    or a path with a dot segment. The proxy must treat such a request as
    malformed and answer it with {!error_response}. *)

val target_uri : target -> string
(** ["https://" ^ host ^ ":" ^ port ^ path], without the port when there is
    none. *)

val check_request :
  meth:string -> headers:(string * string) list -> (unit, Error.t) result
(** Whether a request is a [POST] of type [application/oblivious-dns-message],
    as a proxy must check (Section 4.1). *)

val target_request_headers : (string * string) list
(** The fields of the request to the target: its content type and [accept], and
    nothing else. None of the client's fields is forwarded, so that no cookie,
    authorization, or [forwarded] field reaches the target (Sections 4.5 and
    11.3). *)

val proxy_status :
  name:string ->
  ?error:string ->
  ?details:string ->
  ?received_status:int ->
  unit ->
  string
(** A [proxy-status] field value (RFC 9209) naming the proxy [name], with an
    [error] type such as ["http_request_error"], [details], and the
    [received-status] of the target's response. [name] is written as a token if
    it is one and as a string otherwise, and any character of [name] or
    [details] that a string cannot hold is replaced with [?].

    Raises [Invalid_argument] if [error] is not a token. *)

val response_headers :
  name:string ->
  status:int ->
  headers:(string * string) list ->
  (string * string) list
(** The fields of the answer to the client, given the [status] and [headers] of
    the target's response, whose status and content the proxy forwards unchanged
    (Section 4.3): the target's [content-type], if any,
    [cache-control: no-store], and a [proxy-status] with the target's status as
    [received-status]. *)

val error_response : name:string -> Error.t -> Http_binding.error_response
(** The answer to a request that the proxy does not forward because it is
    malformed: a 405 for {!Error.Method_not_allowed}, a 415 for
    {!Error.Unsupported_media_type}, and a 400 for everything else, each with a
    [proxy-status] of error type [http_request_error] (Section 4.1). *)

val denied :
  name:string -> ?details:string -> unit -> Http_binding.error_response
(** A 403 with a [proxy-status] of error type [http_request_denied]: the answer
    to a request for a target that the proxy's policy refuses, such as one on a
    non-standard port. *)

val unreachable :
  name:string ->
  error:string ->
  ?details:string ->
  unit ->
  Http_binding.error_response
(** A 502 with a [proxy-status] of error type [error], such as ["dns_timeout"],
    ["connection_refused"], or ["tls_protocol_error"]: the answer when the proxy
    cannot reach the target.

    Raises [Invalid_argument] if [error] is not a token. *)
