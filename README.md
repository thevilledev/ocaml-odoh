# odoh

**Oblivious DNS over HTTPS for OCaml.** `odoh` implements
[RFC 9230](https://www.rfc-editor.org/rfc/rfc9230.html), which splits DNS over
HTTPS between two parties that do not collude: a proxy that knows who is asking
but not what, and a target that knows what is asked but not by whom. Queries
are encrypted to the target with HPKE, through the
[`hpke`](https://github.com/thevilledev/ocaml-hpke) package.

```text
            ObliviousDoHMessage, encrypted to the target
  Client ───────────────────► Proxy ───────────────────► Target
         ◄─────────────────── ◄───────────────────
            response, encrypted under a key derived from the query
```

`odoh` is not an HTTP library and not a DNS library, and depends on neither.
Messages are strings, DNS messages included, so any HTTP library can carry
them and any DNS library can build and read what they hold. The
`odoh-cohttp-lwt` package carries them over cohttp-lwt, as a client, a proxy,
and a target in front of a DoH resolver.

> **Status:** unaudited and not production-ready. RFC 9230 is an Experimental
> RFC of the Independent Submission stream, published to enable
> experimentation; the IETF's general mechanism for the same separation is
> Oblivious HTTP (RFC 9458).
> Read the [security notes](SECURITY.md) before using the library. `odoh`
> needs `hpke` 0.4.0, whose release candidate is not on opam yet;
> `opam install .` pins it from its Git tag.

## Try it

You need OCaml **4.14 or later** and an active opam switch:

```sh
git clone https://github.com/thevilledev/ocaml-odoh.git
cd ocaml-odoh
opam install . --deps-only
opam exec -- dune exec examples/basic.exe
```

The [example](examples/basic.ml) runs one exchange through a client, a proxy,
and a target in one process, and shows what each of them would send:

```text
target publishes 46 bytes of ObliviousDoHConfigs
client posts 213 bytes to https://dnsproxy.example/dns-query?targethost=dnstarget.example&targetpath=%2Fdns-query
proxy forwards it to https://dnstarget.example/dns-query
target received DNS query abcd0100…
proxy answers with content-type: application/oblivious-dns-message
proxy answers with cache-control: no-store
proxy answers with proxy-status: dnsproxy.example; received-status=200
client received DNS response abcd8180…
```

## Using it

A target publishes its configurations and answers queries:

```ocaml
let* key = Odoh.Target.Key.generate ~rng Hpke.Kem.X25519 in
let* target = Odoh.Target.create [ key ] in
let published = Odoh.Target.encoded_configs target in
(* For each POST of application/oblivious-dns-message: *)
let* dns_query, context = Odoh.Target.decrypt_query target body in
let* response = Odoh.Target.encrypt_response ~rng context (resolve dns_query) in
```

A client encrypts a query to the target's first configuration and posts it to
the proxy's URI template:

```ocaml
let* config = Odoh.Config.decode_list published |> Result.map List.hd in
let uri = Odoh.Proxy.Template.expand template ~targethost ~targetpath in
let* query, context = Odoh.Client.encrypt_query ~rng config dns_query in
(* POST [query] to [uri] with Odoh.Http_binding.Client.request_headers. *)
let* dns_response = Odoh.Client.decrypt_response context response in
```

A proxy never decrypts anything. It reads the target from the request, and
forwards the body with a fixed set of fields, so that nothing that identifies
the client reaches the target:

```ocaml
let* () = Odoh.Proxy.check_request ~meth ~headers in
let* target = Odoh.Proxy.target_of_request template request_target in
(* Apply the proxy's policy, then POST the body to Odoh.Proxy.target_uri target
   with Odoh.Proxy.target_request_headers. *)
```

`Odoh.Service` puts these steps together as functions from HTTP messages to
HTTP messages, with limits on message sizes and on requests in flight, and
`odoh-cohttp-lwt` runs them over cohttp-lwt:

```ocaml
module C = Odoh_cohttp_lwt.Make (Cohttp_lwt_unix.Client)

(* A target in front of a DoH resolver, and a proxy that forwards only to it. *)
let target =
  Odoh_cohttp_lwt.Target.handler
    (Odoh.Service.Target.create ~rng target_keys)
    (C.Resolver.doh (Uri.of_string "https://resolver.example/dns-query"))

let proxy =
  C.Proxy.handler
    (Odoh.Service.Proxy.create ~template
       ~route:(Odoh.Service.Proxy.allow [ "target.example" ])
       ())

(* A client. *)
let* configs = C.Client.configs (Uri.of_string "https://target.example/.well-known/odohconfigs") in
let* answer = C.Client.query ~rng ~proxy:uri (List.hd configs) dns_query in
```

The [`odoh_target`, `odoh_proxy`, and `odoh_client`](examples/) examples are
these as programs.

Errors that the proxy or target must answer without an encrypted message come
with their status and fields: `Odoh.Http_binding.Target.error_response` (401
for an unknown key, 400 for a query that does not decrypt), and
`Odoh.Proxy.error_response`, `denied`, and `unreachable`, which carry a
`proxy-status` field (RFC 9209).

## What it provides

| Module | RFC 9230 |
| --- | --- |
| `Odoh.Config` | `ObliviousDoHConfigContents`, `ObliviousDoHConfig`, and `ObliviousDoHConfigs`, and the key identifier (Sections 5 and 6.1). Configurations of other versions and with unknown algorithms are skipped. |
| `Odoh.Message` | `ObliviousDoHMessage` and `ObliviousDoHMessagePlaintext`, with zero padding checked, and padding policies after RFC 8467 (Section 6.1). |
| `Odoh.Client`, `Odoh.Target` | Query and response encryption (Sections 6.2, 7, and 8), with key rotation at the target. |
| `Odoh.Proxy` | The proxy URI template with the `targethost` and `targetpath` variables, for clients to expand and proxies to match (RFC 6570, Level 3), the fields to forward, and `proxy-status` (Sections 4.1, 4.3, and 4.5). |
| `Odoh.Http_binding` | The media type, the checks each side makes, and error responses (Section 4). |
| `Odoh.Service` | The client, proxy, and target as steps between HTTP messages, with a proxy's routing policy, limits, and configurations served at `/.well-known/odohconfigs`, where q, doh-server, and odoh-server-go look for them. |
| `Odoh_cohttp_lwt` (package `odoh-cohttp-lwt`) | `Odoh.Service` over cohttp-lwt, with a target resolver that forwards to a DoH server. |

Every KEM of the `hpke` package can be used, including the post-quantum
MLKEM768-X25519 (X-Wing) and the other hybrid and ML-KEM KEMs of
draft-ietf-hpke-pq, with HKDF-SHA256, SHA-384, or SHA-512, and AES-128-GCM,
AES-256-GCM, or ChaCha20Poly1305: 99 suites. The post-quantum ones work only
between clients and targets of this library. The default is the
suite that Section 9 makes mandatory: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
and AES-128-GCM. Queries are padded to a multiple of 128 bytes and responses
to a multiple of 468, as RFC 8467 recommends; RFC 9230 leaves padding to the
implementation.

Not provided: the discovery of targets and proxies
(which RFC 9230 leaves out of scope; the `odohconfig` SvcParam of an HTTPS
record carries the `ObliviousDoHConfigs` that `Odoh.Config.decode_list`
reads), and trial decryption by a target of a query for an unknown key.

## Interoperability

| Implementation | How it is checked |
| --- | --- |
| [cloudflare/odoh-go](https://github.com/cloudflare/odoh-go) (archived) | Its test vectors are reproduced: configuration, key identifier, and every response byte for byte. Live exchanges in both roles over 36 suites. |
| [cloudflare/odoh-rs](https://github.com/cloudflare/odoh-rs) | The same test vectors, which it shares. Live exchanges in both roles over the mandatory suite, the only one it provides. |
| [natesales/q](https://github.com/natesales/q) | Over HTTPS: q queries through the OCaml proxy, to the OCaml target and to doh-server. |
| [DNSCrypt/doh-server](https://github.com/DNSCrypt/doh-server) | Over HTTP: the OCaml client queries it through the OCaml proxy, and the OCaml target resolves through it as a DoH server. |

The live exchanges with the libraries are recorded in [`test/vectors/differential`](test/vectors/differential)
and replayed by `dune test`, so interoperability is checked without the peers.
[`tools/differential`](tools/differential/README.md) runs them again.
[`test/blackbox/run.sh`](test/blackbox/run.sh) runs q and doh-server in Docker,
behind Caddy for TLS, against the example programs.

## Development

```sh
opam exec -- dune build @all @runtest   # build and test
opam exec -- dune build @fmt            # check formatting
opam exec -- dune build --profile fuzz fuzz/fuzz_odoh.exe
_build/default/fuzz/fuzz_odoh.exe --repeat 500
tools/differential/run.sh               # needs Go, and Docker for odoh-rs
test/blackbox/run.sh                    # needs Go, Docker, and cohttp-lwt-unix
```

The tests cover the odoh-go vectors, every suite, tampering with every byte of
a query and a response, the proxy's template matching, and properties over
random input, of which the most important is that no decoder raises.

## License

[ISC](LICENSE). The test vectors in `test/vectors/odoh-go.json` come from
odoh-go, under the MIT licence.
