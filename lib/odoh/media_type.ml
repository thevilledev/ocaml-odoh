let oblivious_dns_message = "application/oblivious-dns-message"

let essence content_type =
  match String.index_opt content_type ';' with
  | None -> content_type
  | Some i -> String.sub content_type 0 i

let matches media_type content_type =
  String.equal
    (String.lowercase_ascii (String.trim (essence content_type)))
    (String.lowercase_ascii media_type)
