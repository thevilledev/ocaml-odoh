#!/bin/sh
# Run the Rust peer. It needs no network, and gets none.
exec docker run --rm -i --network none ocaml-odoh/rust-peer
