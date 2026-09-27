# Security

This library has not received an independent cryptographic audit and is not
production-ready. It is published for interoperability review.

## Scope

- Decoding untrusted input is designed to fail closed. Configurations,
  messages, plaintexts, proxy templates, and request targets are rejected
  unless they are well formed, and none of the decoders raises; this is
  checked by property tests and by fuzzing.
- A target reports every failure that a client can cause after naming a key
  it holds as one error, `Decryption_failed`, whether the HPKE setup failed,
  the query did not open, or its plaintext was malformed or had nonzero
  padding. RFC 9230 answers all of them with a 400, and an unknown key with a
  401. A client reports a response that does not decrypt, or whose padding is
  not zero, in the same way.
- Every query uses a fresh HPKE context. Every response uses a fresh response
  nonce of `max(Nn, Nk)` bytes, drawn from the generator passed as `~rng`; the
  library never reaches for a global one.
- Response contexts are immutable values that hold the encoded query and the
  secret exported for the response, and nothing of the HPKE context.
- A proxy forwards only where its route sends it (`Odoh.Service.Proxy.route`):
  there is no default that forwards anywhere, since that would let clients
  reach whatever the proxy can, internal services included. `allow` accepts a
  list of hosts on port 443.
- The adapters read at most `max_message_size` bytes of any message, refusing
  longer ones from their `content-length` or as they arrive, and handle at
  most `max_in_flight` requests at once.
- The proxy forwards a fixed set of fields to the target, and none of the
  client's, so that cookies, authorization, and `forwarded` fields cannot
  reach the target by mistake (RFC 9230 Sections 4.5 and 11.3). A target's
  host is a DNS name or an IP address, with no user information, and its path
  an absolute path without a query, a fragment, or dot segments.

## Limitations

- RFC 9230 is Experimental. Its security rests on the proxy and the target not
  colluding, which no protocol mechanism enforces.
- Secret key material lives in ordinary OCaml strings and cannot be reliably
  zeroised; the runtime and garbage collector may copy it.
- Configurations are only parsed. A client must obtain them over a channel
  that authenticates the target, and must get the same ones as every other
  client, or the target can tell clients apart.
- Padding hides the length of a DNS message only up to its block size, and
  timing and volume are visible to the proxy. Traffic analysis is out of the
  scope of RFC 9230.
- A target's replies to queries for unknown keys (401) tell a proxy which
  clients have out-of-date configurations. Targets should rotate keys, as
  Section 5 recommends daily, and keep the old key while clients catch up.
- Which targets a proxy forwards to, rate limits, and client authentication
  are the application's to decide (Sections 11.1 to 11.3).
- The adapter serves plain HTTP. RFC 9230 requires HTTPS between every two
  parties, so a deployment puts TLS in front of it, and gives the proxy's
  HTTP client a TLS configuration that verifies targets.
- Post-quantum protection covers only queries that a client encrypts to a
  post-quantum key. The ML-KEM and hybrid KEMs follow draft-ietf-hpke-pq-05,
  which may still change, the ML-KEM implementation of the `mlkem` package is
  as unaudited as this library, and no other ODoH implementation provides
  them.

## Reporting

Report suspected vulnerabilities privately to <ville@vesilehto.fi> rather
than through public issues.
