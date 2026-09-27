# The Rust peer of tools/differential, built where no Rust toolchain is
# installed. See ../README.md.
#
#   docker build -t ocaml-odoh/rust-peer tools/differential/rust
FROM rust:1.90-slim-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release $( [ -f Cargo.lock ] && echo --locked ) \
    && cp target/release/peer /usr/local/bin/peer \
    && cp Cargo.lock /Cargo.lock

FROM debian:bookworm-slim
COPY --from=build /usr/local/bin/peer /usr/local/bin/peer
COPY --from=build /Cargo.lock /Cargo.lock
ENTRYPOINT ["/usr/local/bin/peer"]
