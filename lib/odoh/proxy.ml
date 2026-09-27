(* The proxy's side of an exchange (RFC 9230 Sections 4.1, 4.3, and 4.5). *)

let ( let* ) = Result.bind
let is_alpha c = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
let is_digit c = c >= '0' && c <= '9'
let is_hex c = is_digit c || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')

let is_unreserved c =
  is_alpha c || is_digit c || c = '-' || c = '.' || c = '_' || c = '~'

let is_sub_delim c = String.contains "!$&'()*+,;=" c
let is_reserved c = String.contains ":/?#[]@" c || is_sub_delim c
let is_pchar c = is_unreserved c || is_sub_delim c || c = ':' || c = '@'

let hex_value c =
  if is_digit c then Char.code c - 48
  else Char.code (Char.lowercase_ascii c) - 87

(* Percent-decoding, which fails on a '%' that does not start a triplet. *)
let pct_decode s =
  let n = String.length s in
  let b = Buffer.create n in
  let rec go i =
    if i >= n then Some (Buffer.contents b)
    else if s.[i] <> '%' then (
      Buffer.add_char b s.[i];
      go (i + 1))
    else if i + 2 < n && is_hex s.[i + 1] && is_hex s.[i + 2] then (
      Buffer.add_char b
        (Char.chr ((16 * hex_value s.[i + 1]) + hex_value s.[i + 2]));
      go (i + 3))
    else None
  in
  go 0

module Template = struct
  (* The operators of Level 3 that can hold a variable of the path or the query:
     simple, '+', '/', ';', '?', and '&'. *)
  type op = Simple | Reserved | Path | Param | Query | Continuation
  type part = Literal of string | Expr of op * string list

  type t = {
    source : string;
    origin : string;
    parts : part list;
    match_parts : part list;
  }

  let invalid msg = Error (Error.Invalid_template msg)
  let to_string t = t.source

  (* The character that starts an expansion with the operator, if any. *)
  let leader = function
    | Simple | Reserved -> None
    | Path -> Some '/'
    | Param -> Some ';'
    | Query -> Some '?'
    | Continuation -> Some '&'

  (* RFC 6570 Section 2.1: literals exclude CTL, SP, and these. *)
  let valid_literal_char c =
    Char.code c > 0x20
    && Char.code c < 0x7f
    && not (String.contains "\"'<>\\^`{|}" c)

  let parse_expression body =
    let op, vars =
      match body.[0] with
      | '+' -> (Ok Reserved, String.sub body 1 (String.length body - 1))
      | '/' -> (Ok Path, String.sub body 1 (String.length body - 1))
      | ';' -> (Ok Param, String.sub body 1 (String.length body - 1))
      | '?' -> (Ok Query, String.sub body 1 (String.length body - 1))
      | '&' -> (Ok Continuation, String.sub body 1 (String.length body - 1))
      | '#' | '.' -> (Error "fragment and label expansion are not supported", "")
      | '=' | ',' | '!' | '@' | '|' -> (Error "reserved operator", "")
      | _ -> (Ok Simple, body)
      | exception Invalid_argument _ -> (Error "empty expression", "")
    in
    let* op = Result.map_error (fun m -> Error.Invalid_template m) op in
    let vars = String.split_on_char ',' vars in
    if
      List.exists (fun v -> String.contains v ':' || String.contains v '*') vars
    then invalid "Level 4 modifiers are not allowed"
    else if List.exists (fun v -> v <> "targethost" && v <> "targetpath") vars
    then invalid "variables other than targethost and targetpath"
    else Ok (Expr (op, vars))

  let parse_parts rest =
    let n = String.length rest in
    let rec go i literal acc =
      let flush acc =
        if Buffer.length literal = 0 then acc
        else
          let l = Buffer.contents literal in
          Buffer.clear literal;
          Literal l :: acc
      in
      if i >= n then Ok (List.rev (flush acc))
      else
        match rest.[i] with
        | '{' -> (
            match String.index_from_opt rest i '}' with
            | None -> invalid "unterminated expression"
            | Some j ->
                let acc = flush acc in
                let* expr =
                  parse_expression (String.sub rest (i + 1) (j - i - 1))
                in
                go (j + 1) literal (expr :: acc))
        | '}' -> invalid "unmatched '}'"
        | '#' -> invalid "a fragment"
        | c when valid_literal_char c ->
            Buffer.add_char literal c;
            go (i + 1) literal acc
        | _ -> invalid "invalid character"
    in
    go 0 (Buffer.create 16) []

  let variables parts =
    List.concat_map (function Literal _ -> [] | Expr (_, vs) -> vs) parts

  (* Where the expansion of an expression starts, when that is known: after its
     operator's delimiter, or with the "/" of an absolute path that reserved
     expansion leaves as it is. *)
  let start_of op vars =
    match (op, vars) with
    | Reserved, "targetpath" :: _ -> Some '/'
    | _ -> leader op

  (* Two adjacent expressions can be told apart only by where the second
     starts. *)
  let rec separable = function
    | Expr _ :: (Expr (op, vars) :: _ as rest) ->
        start_of op vars <> None && separable rest
    | _ :: rest -> separable rest
    | [] -> true

  let parse source =
    let n = String.length source in
    if n < 8 || String.lowercase_ascii (String.sub source 0 8) <> "https://"
    then invalid "the scheme is not https"
    else
      let rec authority_end i =
        if i >= n || String.contains "/?{#" source.[i] then i
        else authority_end (i + 1)
      in
      let j = authority_end 8 in
      let authority = String.sub source 8 (j - 8) in
      if authority = "" then invalid "no authority"
      else if not (String.for_all valid_literal_char authority) then
        invalid "invalid character in the authority"
      else
        let* parts = parse_parts (String.sub source j (n - j)) in
        match parts with
        | Expr ((Simple | Reserved | Param | Continuation), _) :: _ ->
            invalid "a variable in the authority"
        | _ ->
            let vars = List.sort String.compare (variables parts) in
            if vars <> [ "targethost"; "targetpath" ] then
              invalid "targethost and targetpath must each appear exactly once"
            else if not (separable parts) then
              invalid "adjacent expressions without a delimiter"
            else
              (* A request always has a path, which is "/" when the template has
                 none before its query. *)
              let match_parts =
                match parts with
                | Literal l :: _ when l.[0] = '?' -> Literal "/" :: parts
                | Expr (Query, _) :: _ -> Literal "/" :: parts
                | _ -> parts
              in
              Ok { source; origin = String.sub source 0 j; parts; match_parts }

  let encode ~reserved s =
    let b = Buffer.create (String.length s) in
    let n = String.length s in
    let rec go i =
      if i < n then
        let c = s.[i] in
        if is_unreserved c then (
          Buffer.add_char b c;
          go (i + 1))
        else if
          reserved && c = '%'
          && i + 2 < n
          && is_hex s.[i + 1]
          && is_hex s.[i + 2]
        then (
          Buffer.add_string b (String.sub s i 3);
          go (i + 3))
        else if reserved && is_reserved c then (
          Buffer.add_char b c;
          go (i + 1))
        else (
          Buffer.add_string b (Printf.sprintf "%%%02X" (Char.code c));
          go (i + 1))
    in
    go 0;
    Buffer.contents b

  let expand_expr op vars value =
    let v name = encode ~reserved:(op = Reserved) (value name) in
    let named name =
      let x = v name in
      match op with Param when x = "" -> name | _ -> name ^ "=" ^ x
    in
    match op with
    | Simple | Reserved -> String.concat "," (List.map v vars)
    | Path -> String.concat "" (List.map (fun n -> "/" ^ v n) vars)
    | Param -> String.concat "" (List.map (fun n -> ";" ^ named n) vars)
    | Query -> "?" ^ String.concat "&" (List.map named vars)
    | Continuation -> String.concat "" (List.map (fun n -> "&" ^ named n) vars)

  let expand t ~targethost ~targetpath =
    let value = function "targethost" -> targethost | _ -> targetpath in
    t.origin
    ^ String.concat ""
        (List.map
           (function
             | Literal l -> l | Expr (op, vars) -> expand_expr op vars value)
           t.parts)

  (* Where the expansion of the part after an expression starts. *)
  let next_start = function
    | Literal l :: _ -> Some l
    | Expr (op, vars) :: _ -> Option.map (String.make 1) (start_of op vars)
    | [] -> None

  let find_from s i needle =
    let n = String.length s and m = String.length needle in
    let rec go j =
      if j + m > n then None
      else if String.sub s j m = needle then Some j
      else go (j + 1)
    in
    go i

  let split_named pieces =
    List.map
      (fun p ->
        match String.index_opt p '=' with
        | None -> (p, "")
        | Some k ->
            (String.sub p 0 k, String.sub p (k + 1) (String.length p - k - 1)))
      pieces

  (* The raw values of the variables of one expression, from its expansion. *)
  let match_expr op vars segment =
    let strip c =
      if segment <> "" && segment.[0] = c then
        Some (String.sub segment 1 (String.length segment - 1))
      else None
    in
    (* One variable takes the whole expansion: reserved expansion leaves any ','
       or '/' in its value as it is. *)
    let positional ~sep s =
      match vars with
      | [ v ] -> Some [ (v, s) ]
      | _ ->
          let pieces = String.split_on_char sep s in
          if List.length pieces = List.length vars then
            Some (List.combine vars pieces)
          else None
    in
    let by_name pieces =
      let pairs = split_named pieces in
      if
        List.length pairs = List.length vars
        && List.sort compare (List.map fst pairs) = List.sort compare vars
      then Some pairs
      else None
    in
    match op with
    | Simple | Reserved -> positional ~sep:',' segment
    | Path -> Option.bind (strip '/') (positional ~sep:'/')
    | Param ->
        Option.bind (strip ';') (fun s -> by_name (String.split_on_char ';' s))
    | Query ->
        Option.bind (strip '?') (fun s -> by_name (String.split_on_char '&' s))
    | Continuation ->
        Option.bind (strip '&') (fun s -> by_name (String.split_on_char '&' s))

  let bindings t request =
    let n = String.length request in
    let rec go parts i acc =
      match parts with
      | [] -> if i = n then Some acc else None
      | Literal l :: rest ->
          let m = String.length l in
          if i + m <= n && String.sub request i m = l then go rest (i + m) acc
          else None
      | Expr (op, vars) :: rest ->
          let stop =
            match (op, next_start rest) with
            | (Query | Continuation), None -> Some n
            | (Query | Continuation), Some s -> find_from request i s
            | _, next ->
                (* The path ends at the query. *)
                let q =
                  Option.value ~default:n (String.index_from_opt request i '?')
                in
                let s =
                  match next with
                  | None -> n
                  | Some s ->
                      Option.value ~default:n (find_from request (i + 1) s)
                in
                Some (min q s)
          in
          Option.bind stop (fun j ->
              Option.bind
                (match_expr op vars (String.sub request i (j - i)))
                (fun b -> go rest j (b @ acc)))
    in
    go t.match_parts 0 []
end

type target = { host : string; port : int option; path : string }

let invalid_target msg = Error (Error.Invalid_target msg)

let valid_reg_name h =
  let labels = String.split_on_char '.' h in
  let labels =
    (* One trailing dot, of a fully qualified name, is allowed. *)
    match List.rev labels with
    | "" :: (_ :: _ as rest) -> List.rev rest
    | _ -> labels
  in
  String.length h <= 254
  && List.for_all
       (fun l ->
         l <> ""
         && String.length l <= 63
         && String.for_all (fun c -> is_alpha c || is_digit c || c = '-') l)
       labels

let valid_ipv6 a =
  a <> "" && String.contains a ':'
  && String.for_all (fun c -> is_hex c || c = ':' || c = '.') a

let parse_port p =
  if p = "" || String.length p > 5 || not (String.for_all is_digit p) then None
  else
    let v = int_of_string p in
    if v >= 1 && v <= 65535 then Some v else None

let parse_host value =
  let n = String.length value in
  let with_port host port =
    match port with
    | None -> Ok (host, None)
    | Some p -> (
        match parse_port p with
        | Some port -> Ok (host, Some port)
        | None -> invalid_target "invalid port")
  in
  if n > 0 && value.[0] = '[' then
    match String.index_opt value ']' with
    | None -> invalid_target "invalid host"
    | Some k ->
        let address = String.sub value 1 (k - 1) in
        let rest = String.sub value (k + 1) (n - k - 1) in
        if not (valid_ipv6 address) then invalid_target "invalid host"
        else if rest = "" then
          with_port (String.lowercase_ascii (String.sub value 0 (k + 1))) None
        else if rest.[0] = ':' then
          with_port
            (String.lowercase_ascii (String.sub value 0 (k + 1)))
            (Some (String.sub rest 1 (String.length rest - 1)))
        else invalid_target "invalid host"
  else
    let host, port =
      match String.rindex_opt value ':' with
      | None -> (value, None)
      | Some k ->
          (String.sub value 0 k, Some (String.sub value (k + 1) (n - k - 1)))
    in
    if valid_reg_name host then with_port (String.lowercase_ascii host) port
    else invalid_target "invalid host"

let valid_path p =
  let n = String.length p in
  let rec chars i =
    if i >= n then true
    else if p.[i] = '%' then
      i + 2 < n && is_hex p.[i + 1] && is_hex p.[i + 2] && chars (i + 3)
    else (is_pchar p.[i] || p.[i] = '/') && chars (i + 1)
  in
  n > 0
  && p.[0] = '/'
  && chars 0
  && List.for_all (fun s -> s <> "." && s <> "..") (String.split_on_char '/' p)

let target_of_request template request =
  match Template.bindings template request with
  | None -> invalid_target "the request does not match the template"
  | Some bindings ->
      let value name =
        match pct_decode (List.assoc name bindings) with
        | Some v -> Ok v
        | None -> invalid_target "invalid percent-encoding"
      in
      let* host = value "targethost" in
      let* path = value "targetpath" in
      let* host, port = parse_host host in
      if valid_path path then Ok { host; port; path }
      else invalid_target "invalid path"

let target_uri t =
  let port = match t.port with None -> "" | Some p -> ":" ^ string_of_int p in
  "https://" ^ t.host ^ port ^ t.path

let check_request = Http_binding.Target.check_request

let target_request_headers =
  [
    ("content-type", Media_type.oblivious_dns_message);
    ("accept", Media_type.oblivious_dns_message);
  ]

(* Structured field values (RFC 8941) of RFC 9209. *)
let is_tchar c = is_alpha c || is_digit c || String.contains "!#$%&'*+-.^_`|~" c

let is_token s =
  s <> ""
  && (is_alpha s.[0] || s.[0] = '*')
  && String.for_all (fun c -> is_tchar c || c = ':' || c = '/') s

let sf_string s =
  let b = Buffer.create (String.length s + 2) in
  Buffer.add_char b '"';
  String.iter
    (fun c ->
      match c with
      | '"' | '\\' ->
          Buffer.add_char b '\\';
          Buffer.add_char b c
      | c when Char.code c >= 0x20 && Char.code c < 0x7f -> Buffer.add_char b c
      | _ -> Buffer.add_char b '?')
    s;
  Buffer.add_char b '"';
  Buffer.contents b

let proxy_status ~name ?error ?details ?received_status () =
  let params =
    List.concat
      [
        (match error with
        | None -> []
        | Some e ->
            if not (is_token e) then
              invalid_arg "Odoh.Proxy.proxy_status: error";
            [ "error=" ^ e ]);
        (match received_status with
        | None -> []
        | Some s -> [ "received-status=" ^ string_of_int s ]);
        (match details with
        | None -> []
        | Some d -> [ "details=" ^ sf_string d ]);
      ]
  in
  String.concat "; " ((if is_token name then name else sf_string name) :: params)

let response_headers ~name ~status ~headers =
  let content_type =
    match Http_binding.header headers "content-type" with
    | None -> []
    | Some ty -> [ ("content-type", ty) ]
  in
  content_type
  @ [
      ("cache-control", "no-store");
      ("proxy-status", proxy_status ~name ~received_status:status ());
    ]

let error_with ~name ~status ~error ?details extra =
  {
    Http_binding.status;
    headers =
      ("cache-control", "no-store")
      :: ("proxy-status", proxy_status ~name ~error ?details ())
      :: extra;
    body = "";
  }

let error_response ~name (e : Error.t) =
  let status, extra =
    match e with
    | Method_not_allowed _ -> (405, [ ("allow", "POST") ])
    | Unsupported_media_type _ ->
        (415, [ ("accept", Media_type.oblivious_dns_message) ])
    | _ -> (400, [])
  in
  error_with ~name ~status ~error:"http_request_error"
    ~details:(Error.to_string e) extra

let denied ~name ?details () =
  error_with ~name ~status:403 ~error:"http_request_denied" ?details []

let unreachable ~name ~error ?details () =
  error_with ~name ~status:502 ~error ?details []
