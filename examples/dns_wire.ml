(* Just enough of the DNS wire format (RFC 1035) for the example client: a query
   for one name, and the addresses in an answer. A real client uses a DNS
   library. *)

let qtype_of_string = function
  | "A" -> 1
  | "AAAA" -> 28
  | "TXT" -> 16
  | t -> failwith ("unsupported type " ^ t)

let query ~id ~name ~qtype =
  let b = Buffer.create 64 in
  Buffer.add_uint16_be b id;
  Buffer.add_uint16_be b 0x0100 (* RD *);
  Buffer.add_uint16_be b 1;
  Buffer.add_string b "\x00\x00\x00\x00\x00\x00";
  List.iter
    (fun label ->
      if label <> "" then (
        Buffer.add_uint8 b (String.length label);
        Buffer.add_string b label))
    (String.split_on_char '.' name);
  Buffer.add_uint8 b 0;
  Buffer.add_uint16_be b qtype;
  Buffer.add_uint16_be b 1;
  Buffer.contents b

let rcode_name = function
  | 0 -> "NOERROR"
  | 1 -> "FORMERR"
  | 2 -> "SERVFAIL"
  | 3 -> "NXDOMAIN"
  | 5 -> "REFUSED"
  | n -> string_of_int n

(* The position after a name, which may end in a compression pointer. *)
let rec skip_name s i =
  let len = Char.code s.[i] in
  if len = 0 then i + 1
  else if len land 0xc0 = 0xc0 then i + 2
  else skip_name s (i + 1 + len)

let address qtype data =
  match (qtype, String.length data) with
  | 1, 4 ->
      String.concat "."
        (List.init 4 (fun i -> string_of_int (Char.code data.[i])))
  | 28, 16 ->
      String.concat ":"
        (List.init 8 (fun i ->
             Printf.sprintf "%x" (String.get_uint16_be data (2 * i))))
  | 16, _ -> Printf.sprintf "%S" (String.sub data 1 (String.length data - 1))
  | _ -> "?"

(* The identifier, the RCODE, and the answers of a response. *)
let answers s =
  let id = String.get_uint16_be s 0 in
  let rcode = Char.code s.[3] land 0x0f in
  let qdcount = String.get_uint16_be s 4 in
  let ancount = String.get_uint16_be s 6 in
  let i = ref 12 in
  for _ = 1 to qdcount do
    i := skip_name s !i + 4
  done;
  let answers =
    List.init ancount (fun _ ->
        let j = skip_name s !i in
        let qtype = String.get_uint16_be s j in
        let rdlength = String.get_uint16_be s (j + 8) in
        let data = String.sub s (j + 10) rdlength in
        i := j + 10 + rdlength;
        address qtype data)
  in
  (id, rcode_name rcode, answers)
