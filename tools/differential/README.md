# Differential testing

`differential.exe` runs Oblivious DoH exchanges between `odoh` and other
implementations of RFC 9230, in both roles:

- the OCaml client queries the peer as the target, and opens its response;
- the peer queries the OCaml target as a client, and opens the OCaml response.

For every exchange it checks that both sides agree on the configuration, the
key identifier, the query, its padding, and the response. Any disagreement is
printed, and the driver exits with status 1.

| Peer | Implementation | Suites |
| --- | --- | --- |
| `go` | [cloudflare/odoh-go](https://github.com/cloudflare/odoh-go) at `f39fa01` (archived) | 36: X25519, X448, P-256, and P-521, with every KDF and AEAD |
| `rust` | [cloudflare/odoh-rs](https://github.com/cloudflare/odoh-rs) at `91f079f` | 1: X25519, HKDF-SHA256, AES-128-GCM |

odoh-go's configuration parser does not know P-384, and odoh-rs provides only
the suite that RFC 9230 Section 9 makes mandatory. No peer provides ML-KEM or the hybrid KEMs.

## Running

```sh
tools/differential/run.sh
```

builds the Go peer with the Go toolchain, the Rust peer as a Docker image
(`docker run --network none`), and the driver, and runs every peer that can be
built.

```sh
tools/differential/run.sh --record test/vectors/differential
```

also writes each peer's exchanges to `test/vectors/differential/NAME.json`.
`test/test_differential.ml` replays them without the peers: the OCaml client's
queries are made with a deterministic HPKE sender, so they can be rebuilt byte
for byte and the peer's recorded response opened again, and the OCaml target's
responses use a chosen nonce, so they can be rebuilt byte for byte too.

## The protocol

A peer reads one JSON object per line on standard input, and answers each with
one line on standard output: `{"ok": true, ...}` or
`{"ok": false, "error": "..."}`. Byte strings are lowercase hexadecimal.

| `op` | Arguments | Answer |
| --- | --- | --- |
| `hello` | | `implementation`, `version` |
| `target` | `kem`, `kdf`, `aead`, `seed`, `query`, `response`, `response_padding` | `configs`, `key_id`, `query`, `query_padding`, `response` |
| `query` | `handle`, `configs`, `query`, `padding` | `query` |
| `open` | `handle`, `response` | `response` |

`target` derives the key from `seed` with `DeriveKeyPair`, decrypts the
`ObliviousDoHMessage` `query`, and encrypts the DNS message `response` to it.
`query` encrypts a DNS query to the first supported configuration of
`configs` and keeps the context under `handle`, which `open` uses to decrypt
the response.
