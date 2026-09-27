(* TLS-style presentation language (RFC 8446 Section 3): big-endian integers and
   vectors with a 16-bit length prefix. Readers raise [Malformed] with the name
   of what they could not read; [run] turns that into a result, so no decoder of
   the library raises. *)

exception Malformed of string

type cursor = { data : string; mutable pos : int }

let remaining c = String.length c.data - c.pos
let at_end c = remaining c = 0

let u8 what c =
  if remaining c < 1 then raise (Malformed what);
  let v = Char.code c.data.[c.pos] in
  c.pos <- c.pos + 1;
  v

let u16 what c =
  if remaining c < 2 then raise (Malformed what);
  let v = String.get_uint16_be c.data c.pos in
  c.pos <- c.pos + 2;
  v

let bytes what c n =
  if remaining c < n then raise (Malformed what);
  let v = String.sub c.data c.pos n in
  c.pos <- c.pos + n;
  v

let opaque16 what c = bytes what c (u16 what c)

let run f data =
  let c = { data; pos = 0 } in
  match f c with
  | v -> if at_end c then Ok v else Error "trailing bytes"
  | exception Malformed what -> Error ("truncated " ^ what)

let max_u16 = 0xffff

let add_opaque16 b s =
  Buffer.add_uint16_be b (String.length s);
  Buffer.add_string b s

let u16_string n =
  let b = Bytes.create 2 in
  Bytes.set_uint16_be b 0 n;
  Bytes.unsafe_to_string b

let opaque16_string s = u16_string (String.length s) ^ s
