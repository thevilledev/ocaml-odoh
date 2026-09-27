type t =
  | Invalid_config of string
  | Unsupported_version of int
  | Unsupported_suite of { kem : int; kdf : int; aead : int }
  | Malformed_message of string
  | Unexpected_message_type of int
  | Invalid_dns_message of string
  | Unknown_key_id
  | Decryption_failed
  | Content_too_large of int
  | Method_not_allowed of string
  | Unsupported_media_type of string option
  | Unexpected_status of int
  | Unexpected_content_type of string option
  | Invalid_template of string
  | Invalid_target of string
  | Hpke of Hpke.Error.t

let pp_content_type fmt = function
  | None -> Format.pp_print_string fmt "none"
  | Some s -> Format.fprintf fmt "%S" s

let pp fmt = function
  | Invalid_config msg -> Format.fprintf fmt "invalid configuration: %s" msg
  | Unsupported_version v ->
      Format.fprintf fmt "unsupported Oblivious DoH version 0x%04x" v
  | Unsupported_suite { kem; kdf; aead } ->
      Format.fprintf fmt
        "unsupported HPKE suite: KEM 0x%04x, KDF 0x%04x, AEAD 0x%04x" kem kdf
        aead
  | Malformed_message msg -> Format.fprintf fmt "malformed message: %s" msg
  | Unexpected_message_type ty ->
      Format.fprintf fmt "unexpected message type 0x%02x" ty
  | Invalid_dns_message msg -> Format.fprintf fmt "invalid DNS message: %s" msg
  | Unknown_key_id -> Format.pp_print_string fmt "unknown key identifier"
  | Decryption_failed -> Format.pp_print_string fmt "decryption failed"
  | Content_too_large limit ->
      Format.fprintf fmt "content longer than %d bytes" limit
  | Method_not_allowed meth -> Format.fprintf fmt "method %S not allowed" meth
  | Unsupported_media_type ty ->
      Format.fprintf fmt "unsupported media type %a" pp_content_type ty
  | Unexpected_status status -> Format.fprintf fmt "unexpected status %d" status
  | Unexpected_content_type ty ->
      Format.fprintf fmt "unexpected content type %a" pp_content_type ty
  | Invalid_template msg -> Format.fprintf fmt "invalid URI template: %s" msg
  | Invalid_target msg -> Format.fprintf fmt "invalid target: %s" msg
  | Hpke e -> Format.fprintf fmt "HPKE: %a" Hpke.Error.pp e

let to_string e = Format.asprintf "%a" pp e
