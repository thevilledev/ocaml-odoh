# Changelog

## 0.1.0 — unreleased

- Add `odoh`, an implementation of Oblivious DNS over HTTPS (RFC 9230) with no
  I/O: target configurations in their three encodings and the key identifier,
  messages and zero-padded plaintexts, query and response encryption for
  clients and targets over every suite of the `hpke` package, and padding
  policies after RFC 8467.
- Provide the post-quantum KEMs of draft-ietf-hpke-pq-05 through `hpke`
  0.4.0: MLKEM768-X25519 (X-Wing), MLKEM768-P256, MLKEM1024-P384, and ML-KEM,
  beside the Diffie-Hellman KEMs. No other ODoH implementation provides them.
- Add `Odoh.Proxy`: proxy URI templates, which clients expand and proxies
  match to find the target, the fields a proxy forwards, and `proxy-status`
  fields for its answers.
- Add `Odoh.Http_binding`: the media type, the checks of each side, and the
  error responses of RFC 9230 Section 4.
- Add `Odoh.Service`: the client, proxy, and target as steps between HTTP
  messages, without I/O, with a proxy's routing policy, limits on message
  sizes and requests in flight, configurations at `/.well-known/odohconfigs`,
  and a SERVFAIL for a target whose resolver fails.
- Add `odoh-cohttp-lwt`: a client, a proxy handler, a target handler, and a
  target resolver that forwards to a DoH server, over cohttp-lwt. Example
  programs over cohttp-lwt-unix pass black-box tests against the q client and
  doh-server.
- Reproduce the test vectors of odoh-go and odoh-rs, and check exchanges in
  both roles against both of them in `tools/differential`, whose recordings
  the tests replay.
