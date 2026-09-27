(** How Oblivious DoH messages travel over HTTP (RFC 9230 Section 4).

    Nothing here performs I/O: these are the fields to send, and the checks to
    make on what comes back, for whichever HTTP library carries the messages.
    Fields are pairs of a lowercase name and a value. The proxy's part is in
    {!Proxy}. *)

val max_message_length : int
(** The length of the longest [ObliviousDoHMessage] that a 16-bit key identifier
    and a 16-bit encrypted message can make: a bound on the content of any
    request or response, which an HTTP server can enforce before reading it. *)

val header : (string * string) list -> string -> string option
(** [header headers name] is the value of the first field named [name], compared
    without regard to case. *)

type error_response = {
  status : int;
  headers : (string * string) list;
  body : string;
}
(** An answer that carries no encrypted message. *)

module Client : sig
  val request_headers : (string * string) list
  (** The fields of the [POST] that carries a query to the proxy: its content
      type, and the same media type in [accept] (RFC 9230 Section 4.1). A client
      must add nothing that identifies it, such as cookies (Section 4.5). *)

  val check_response :
    status:int -> headers:(string * string) list -> (unit, Error.t) result
  (** Whether an answer carries an encrypted response: a 2xx of type
      [application/oblivious-dns-message]. Anything else must be treated as an
      error (Section 4.3). A 401 from the target means that the configuration
      used is out of date. A 3xx must be followed, if at all, through a proxy
      again. *)
end

module Target : sig
  val check_request :
    meth:string -> headers:(string * string) list -> (unit, Error.t) result
  (** Whether a request carries a query: a [POST] of type
      [application/oblivious-dns-message] (Section 4.1). *)

  val response_headers : (string * string) list
  (** The fields of the 200 that carries an encrypted response: its content
      type, and [cache-control: no-store], since neither queries nor responses
      may be cached (Section 4.1). *)

  val error_response : Error.t -> error_response
  (** The answer to a query that the target could not decrypt, which therefore
      cannot be encrypted itself (Section 4.3): a 401 for
      {!Error.Unknown_key_id}, a 405 or 415 for a request that {!check_request}
      refuses, a 413 for {!Error.Content_too_large}, a 500 for a failure that is
      not the client's doing, and a 400 for everything else. *)
end
