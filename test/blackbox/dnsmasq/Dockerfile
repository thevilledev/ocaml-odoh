# The resolver at the bottom of every black-box exchange: answers for
# example.test, and NXDOMAIN for every other name, with no
# upstream.
FROM alpine:3.20
RUN apk add --no-cache dnsmasq
ENTRYPOINT ["dnsmasq", "--keep-in-foreground", "--no-resolv", "--no-hosts", \
  "--log-queries", "--log-facility=-", \
  "--address=/example.test/192.0.2.53", \
  "--address=/example.test/2001:db8::53", \
  "--txt-record=example.test,oblivious", \
  "--address=/#/"]
