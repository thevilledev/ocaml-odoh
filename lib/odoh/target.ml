(* The target's side of an exchange (RFC 9230 Section 8). *)

open Exchange

module Key = struct
  type t = { private_key : Hpke.Private_key.t; config : Config.t }

  let of_private_key ?kdf ?aead private_key =
    {
      private_key;
      config =
        Config.create ?kdf ?aead (Hpke.Private_key.public_key private_key);
    }

  let generate ~rng ?kdf ?aead kem =
    let* private_key, _ = hpke (Hpke.generate_key_pair ~rng kem) in
    Ok (of_private_key ?kdf ?aead private_key)

  let derive ?kdf ?aead kem ~ikm =
    let* private_key, _ = hpke (Hpke.derive_key_pair kem ~ikm) in
    Ok (of_private_key ?kdf ?aead private_key)

  let config t = t.config
  let key_id t = Config.key_id t.config
end

type t = Key.t list

let create = function
  | [] -> Error (Error.Invalid_config "no keys")
  | keys ->
      let ids = List.map Key.key_id keys in
      if List.length (List.sort_uniq String.compare ids) <> List.length ids then
        Error (Error.Invalid_config "duplicate key")
      else Ok keys

let configs t = List.map Key.config t
let encoded_configs t = Config.encode_list (configs t)

type context = Exchange.secret

let open_query (key : Key.t) (message : Message.t) =
  let suite = Config.suite key.config in
  let nenc = Hpke.Kem.encapsulated_key_size suite.kem in
  let encrypted = message.encrypted_message in
  if String.length encrypted < nenc then Error Error.Decryption_failed
  else
    let encapsulated_key = String.sub encrypted 0 nenc in
    let ciphertext =
      String.sub encrypted nenc (String.length encrypted - nenc)
    in
    match
      Hpke.Rfc9180.setup_base_receiver (Suite.hpke suite)
        ~recipient:key.private_key ~encapsulated_key ~info:label_query
    with
    | Error _ -> Error Error.Decryption_failed
    | Ok receiver -> (
        match
          Hpke.Rfc9180.Receiver.open_ receiver ~aad:(query_aad message.key_id)
            ~ciphertext
        with
        | Error _ -> Error Error.Decryption_failed
        | Ok query ->
            let* plaintext = Message.Plaintext.decode query in
            let* secret =
              hpke
                (Hpke.Rfc9180.Receiver.export receiver ~context:label_response
                   ~length:(secret_length suite))
            in
            Ok (plaintext.dns_message, { suite; query; secret }))

let decrypt_query t query =
  let* message = Message.decode query in
  match message.message_type with
  | Response -> Error (Error.Unexpected_message_type 0x02)
  | Query -> (
      match
        List.find_opt (fun k -> String.equal (Key.key_id k) message.key_id) t
      with
      | None -> Error Error.Unknown_key_id
      | Some key -> open_query key message)

let encrypt_response ~rng ?(padding = Message.Padding.response) context
    dns_response =
  let* plaintext = Message.Plaintext.make ~padding dns_response in
  let nonce =
    Mirage_crypto_rng.generate ~g:rng
      (Suite.response_nonce_length context.suite)
  in
  let* key, aead_nonce = derive context nonce in
  let* ciphertext =
    hpke
      (Hpke.Aead.seal key ~nonce:aead_nonce ~aad:(response_aad nonce)
         ~plaintext:(Message.Plaintext.encode plaintext))
  in
  if String.length ciphertext > Wire.max_u16 then
    Error (Error.Invalid_dns_message "too long")
  else
    Ok
      (Message.encode
         {
           message_type = Response;
           key_id = nonce;
           encrypted_message = ciphertext;
         })
