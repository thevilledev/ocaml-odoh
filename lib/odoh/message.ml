(* Oblivious DoH messages (RFC 9230 Section 6.1). *)

type message_type = Query | Response

let message_type_to_int = function Query -> 0x01 | Response -> 0x02

type t = {
  message_type : message_type;
  key_id : string;
  encrypted_message : string;
}

let encode t =
  if String.length t.key_id > Wire.max_u16 then
    invalid_arg "Odoh.Message.encode: key_id too long";
  let n = String.length t.encrypted_message in
  if n = 0 || n > Wire.max_u16 then
    invalid_arg "Odoh.Message.encode: encrypted_message length";
  let b = Buffer.create (5 + String.length t.key_id + n) in
  Buffer.add_uint8 b (message_type_to_int t.message_type);
  Wire.add_opaque16 b t.key_id;
  Wire.add_opaque16 b t.encrypted_message;
  Buffer.contents b

let decode s =
  let read c =
    let ty = Wire.u8 "message type" c in
    let key_id = Wire.opaque16 "key identifier" c in
    let encrypted_message = Wire.opaque16 "encrypted message" c in
    (ty, key_id, encrypted_message)
  in
  match Wire.run read s with
  | Error msg -> Error (Error.Malformed_message msg)
  | Ok (_, _, "") -> Error (Error.Malformed_message "empty encrypted message")
  | Ok (ty, key_id, encrypted_message) -> (
      match ty with
      | 0x01 -> Ok { message_type = Query; key_id; encrypted_message }
      | 0x02 -> Ok { message_type = Response; key_id; encrypted_message }
      | ty -> Error (Error.Unexpected_message_type ty))

module Padding = struct
  type t = Block of int | Fixed of int

  let none = Fixed 0

  let block n =
    if n < 1 || n > Wire.max_u16 then invalid_arg "Odoh.Message.Padding.block";
    Block n

  let fixed n =
    if n < 0 || n > Wire.max_u16 then invalid_arg "Odoh.Message.Padding.fixed";
    Fixed n

  let query = Block 128
  let response = Block 468

  (* The encoded plaintext is the DNS message and the padding, each behind a
     two-byte length. *)
  let length t dns_length =
    match t with
    | Fixed n -> n
    | Block n ->
        let unpadded = 4 + dns_length in
        (n - (unpadded mod n)) mod n
end

module Plaintext = struct
  type t = { dns_message : string; padding_length : int }

  let make ?(padding = Padding.none) dns_message =
    let n = String.length dns_message in
    let padding_length = Padding.length padding n in
    if n = 0 then Error (Error.Invalid_dns_message "empty")
    else if n > Wire.max_u16 then Error (Error.Invalid_dns_message "too long")
    else if padding_length > Wire.max_u16 then
      Error (Error.Invalid_dns_message "padding too long")
    else Ok { dns_message; padding_length }

  let encode t =
    let b =
      Buffer.create (4 + String.length t.dns_message + t.padding_length)
    in
    Wire.add_opaque16 b t.dns_message;
    Buffer.add_uint16_be b t.padding_length;
    Buffer.add_string b (String.make t.padding_length '\x00');
    Buffer.contents b

  (* The padding is checked without branching on its bytes, as odoh-go does: the
     plaintext is authenticated, but nothing is lost by not timing it. *)
  let all_zero s =
    let acc = ref 0 in
    String.iter (fun c -> acc := !acc lor Char.code c) s;
    !acc = 0

  let decode s =
    let read c =
      let dns_message = Wire.opaque16 "DNS message" c in
      let padding = Wire.opaque16 "padding" c in
      (dns_message, padding)
    in
    match Wire.run read s with
    | Ok (dns_message, padding) when dns_message <> "" && all_zero padding ->
        Ok { dns_message; padding_length = String.length padding }
    | Ok _ | Error _ -> Error Error.Decryption_failed
end
