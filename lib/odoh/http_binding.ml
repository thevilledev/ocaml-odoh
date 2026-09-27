(* How Oblivious DoH messages travel over HTTP (RFC 9230 Section 4). *)

(* message_type, key_id<0..2^16-1>, encrypted_message<1..2^16-1> *)
let max_message_length = 1 + 2 + 0xffff + 2 + 0xffff
let media_type = Media_type.oblivious_dns_message

let header headers name =
  List.find_map
    (fun (k, v) ->
      if String.equal (String.lowercase_ascii k) name then Some v else None)
    headers

let has_media_type headers =
  match header headers "content-type" with
  | Some ty when Media_type.matches media_type ty -> Ok ()
  | ty -> Error ty

type error_response = {
  status : int;
  headers : (string * string) list;
  body : string;
}

module Client = struct
  let request_headers = [ ("content-type", media_type); ("accept", media_type) ]

  let check_response ~status ~headers =
    if status < 200 || status > 299 then Error (Error.Unexpected_status status)
    else
      Result.map_error
        (fun ty -> Error.Unexpected_content_type ty)
        (has_media_type headers)
end

module Target = struct
  let check_request ~meth ~headers =
    if not (String.equal meth "POST") then Error (Error.Method_not_allowed meth)
    else
      Result.map_error
        (fun ty -> Error.Unsupported_media_type ty)
        (has_media_type headers)

  let response_headers =
    [ ("content-type", media_type); ("cache-control", "no-store") ]

  let error_response e =
    let status, headers =
      match (e : Error.t) with
      | Unknown_key_id -> (401, [])
      | Method_not_allowed _ -> (405, [ ("allow", "POST") ])
      | Unsupported_media_type _ -> (415, [ ("accept", media_type) ])
      | Content_too_large _ -> (413, [])
      | Hpke _ -> (500, [])
      | Invalid_config _ | Unsupported_version _ | Unsupported_suite _
      | Malformed_message _ | Unexpected_message_type _ | Invalid_dns_message _
      | Decryption_failed | Unexpected_status _ | Unexpected_content_type _
      | Invalid_template _ | Invalid_target _ ->
          (400, [])
    in
    { status; headers = ("cache-control", "no-store") :: headers; body = "" }
end
