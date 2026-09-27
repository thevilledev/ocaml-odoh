(lang dune 3.12)
(name odoh)
(generate_opam_files false)
(source (github thevilledev/ocaml-odoh))
(license ISC)
(authors "Ville Vesilehto <ville@vesilehto.fi>")
(maintainers "Ville Vesilehto <ville@vesilehto.fi>")

(package
 (name odoh)
 (synopsis "Oblivious DNS over HTTPS (RFC 9230) for OCaml")
 (description
  "An implementation of Oblivious DNS over HTTPS (RFC 9230): target configurations, query and response encryption for clients and targets over the hpke package, and the forwarding rules of the proxy. It performs no I/O and does not parse DNS, so any HTTP library and any DNS library can carry the messages.")
 (tags (cryptography privacy dns odoh rfc9230 "oblivious doh" hpke)))

(package
 (name odoh-cohttp-lwt)
 (synopsis "Oblivious DNS over HTTPS (RFC 9230) clients, proxies, and targets over cohttp-lwt")
 (tags (dns odoh rfc9230 "oblivious doh" cohttp lwt)))
