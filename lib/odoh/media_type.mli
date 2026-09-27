(** The media type of Oblivious DoH (RFC 9230 Section 12.1). *)

val oblivious_dns_message : string
(** ["application/oblivious-dns-message"]: an encoded [ObliviousDoHMessage], as
    a query or a response. *)

val matches : string -> string -> bool
(** [matches media_type content_type] is [true] when the [Content-Type] field
    value [content_type] names [media_type]. Type and subtype are compared
    without regard to case, and parameters and surrounding whitespace are
    ignored (RFC 9110 Section 8.3.1). *)
