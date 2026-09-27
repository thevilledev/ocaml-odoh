(* The client's side of an exchange (RFC 9230 Section 7). *)

open Exchange

type context = Exchange.secret

type sender_setup =
  Hpke.Suite.encryption Hpke.Suite.t ->
  recipient:Hpke.Public_key.t ->
  info:string ->
  (Hpke.Suite.encryption Hpke.Rfc9180.sender_setup, Hpke.Error.t) result

let encrypt_query_with ~(setup : sender_setup)
    ?(padding = Message.Padding.query) config dns_query =
  let* plaintext = Message.Plaintext.make ~padding dns_query in
  let query = Message.Plaintext.encode plaintext in
  let suite = Config.suite config in
  let* { Hpke.Rfc9180.encapsulated_key; context } =
    hpke
      (setup (Suite.hpke suite) ~recipient:(Config.public_key config)
         ~info:label_query)
  in
  let key_id = Config.key_id config in
  let* ciphertext =
    hpke
      (Hpke.Rfc9180.Sender.seal context ~aad:(query_aad key_id) ~plaintext:query)
  in
  let* secret =
    hpke
      (Hpke.Rfc9180.Sender.export context ~context:label_response
         ~length:(secret_length suite))
  in
  let encrypted_message = encapsulated_key ^ ciphertext in
  if String.length encrypted_message > Wire.max_u16 then
    Error (Error.Invalid_dns_message "too long")
  else
    Ok
      ( Message.encode { message_type = Query; key_id; encrypted_message },
        { suite; query; secret } )

let encrypt_query ~rng ?padding config dns_query =
  encrypt_query_with
    ~setup:(Hpke.Rfc9180.setup_base_sender ~rng)
    ?padding config dns_query

let decrypt_response context response =
  let* message = Message.decode response in
  match message.message_type with
  | Query -> Error (Error.Unexpected_message_type 0x01)
  | Response -> (
      let nonce = message.key_id in
      if String.length nonce <> Suite.response_nonce_length context.suite then
        Error Error.Decryption_failed
      else
        let* key, aead_nonce = derive context nonce in
        match
          Hpke.Aead.open_ key ~nonce:aead_nonce ~aad:(response_aad nonce)
            ~ciphertext:message.encrypted_message
        with
        | Error _ -> Error Error.Decryption_failed
        | Ok plaintext ->
            let* plaintext = Message.Plaintext.decode plaintext in
            Ok plaintext.dns_message)
