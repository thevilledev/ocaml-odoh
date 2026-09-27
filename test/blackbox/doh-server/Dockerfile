# DNSCrypt/doh-server, which is a DoH resolver and an ODoH target at once,
# pinned to a commit.
FROM rust:1.90-slim-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo install --locked --git https://github.com/DNSCrypt/doh-server \
      --rev 470edd939b750f38ded944e902502c9d567dcaac doh-proxy

FROM debian:bookworm-slim
COPY --from=build /usr/local/cargo/bin/doh-proxy /usr/local/bin/doh-proxy
ENTRYPOINT ["/usr/local/bin/doh-proxy"]
