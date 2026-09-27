#!/bin/sh
# Black-box interoperability over real HTTP, between the OCaml tools of
# examples/ and two implementations that were not written with them:
#
#   q           github.com/natesales/q, a DNS client with an ODoH transport
#   doh-server  github.com/DNSCrypt/doh-server, a DoH resolver and ODoH target
#
# dnsmasq answers for example.test at the bottom of every exchange, and Caddy
# terminates TLS in front of the OCaml proxy and target, which run on this
# machine, and of doh-server, since q speaks ODoH only over HTTPS.
#
#   test/blackbox/run.sh
#
# Needs Docker, Go, and the opam switch of the project with cohttp-lwt-unix,
# and network access the first time, for images, crates, and modules.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
out=${BLACKBOX_BUILD_DIR:-$root/_build/blackbox}
mkdir -p "$out"

q_version=dce1a72e3413d5e91d0dc16f28bcf7c4d3d8ddde
export TARGET_PORT=${TARGET_PORT:-18080}
export PROXY_PORT=${PROXY_PORT:-18081}
export DOH_PORT=${DOH_PORT:-13000}

echo "== building"
(cd "$root" && opam exec -- dune build ./examples/odoh_target.exe \
  ./examples/odoh_proxy.exe ./examples/odoh_client.exe)
bin=$root/_build/default/examples
[ -x "$out/q" ] || GOBIN="$out" go install "github.com/natesales/q@$q_version"
(cd "$here" && docker compose build -q)

pids=""
cleanup() {
  for pid in $pids; do kill "$pid" 2>/dev/null || true; done
  (cd "$here" && docker compose down -t 1 >/dev/null 2>&1) || true
}
trap cleanup EXIT INT TERM

echo "== starting"
(cd "$here" && docker compose up -d --wait >/dev/null 2>&1)
"$bin/odoh_target.exe" --listen "$TARGET_PORT" \
  --resolver "http://127.0.0.1:$DOH_PORT/dns-query" >"$out/target.log" 2>&1 &
pids="$pids $!"
# localhost:8444 is the OCaml target and localhost:8445 doh-server, both
# behind Caddy; the proxy reaches them without it. Anything else is refused.
"$bin/odoh_proxy.exe" --listen "$PROXY_PORT" \
  --template 'https://localhost:8443/proxy{?targethost,targetpath}' \
  --route "localhost:8444=http://127.0.0.1:$TARGET_PORT" \
  --route "localhost:8445=http://127.0.0.1:$DOH_PORT" \
  --route "ocaml-target.test=http://127.0.0.1:$TARGET_PORT" \
  --route "doh-server.test=http://127.0.0.1:$DOH_PORT" \
  >"$out/proxy.log" 2>&1 &
pids="$pids $!"
for i in 1 2 3 4 5 6 7 8 9 10; do
  curl -sf "http://127.0.0.1:$TARGET_PORT/.well-known/odohconfigs" >/dev/null && break
  sleep 0.5
done

failures=0
check() {
  name=$1 expected=$2
  shift 2
  if output=$("$@" 2>&1) && printf '%s' "$output" | grep -q -- "$expected"; then
    echo "ok    $name"
  else
    echo "FAIL  $name"
    printf '%s\n' "$output" | sed 's/^/      /'
    failures=$((failures + 1))
  fi
}

# The same, for a command that must fail with [expected] in its output.
check_fails() {
  name=$1 expected=$2
  shift 2
  if output=$("$@" 2>&1); then
    echo "FAIL  $name: succeeded"
    printf '%s\n' "$output" | sed 's/^/      /'
    failures=$((failures + 1))
  elif printf '%s' "$output" | grep -q -- "$expected"; then
    echo "ok    $name"
  else
    echo "FAIL  $name"
    printf '%s\n' "$output" | sed 's/^/      /'
    failures=$((failures + 1))
  fi
}

q() { "$out/q" -i --format=raw "$@"; }
client() {
  "$bin/odoh_client.exe" \
    --template 'https://localhost:8443/proxy{?targethost,targetpath}' \
    --proxy-origin "http://127.0.0.1:$PROXY_PORT" "$@"
}

echo "== q (client) -> OCaml proxy -> OCaml target -> doh-server (DoH)"
check "A" "192.0.2.53" q example.test A @https://localhost:8444/dns-query -p https://localhost:8443/proxy
check "AAAA" "2001:db8::53" q example.test AAAA @https://localhost:8444/dns-query -p https://localhost:8443/proxy
check "TXT" "oblivious" q example.test TXT @https://localhost:8444/dns-query -p https://localhost:8443/proxy
check "NXDOMAIN" "NXDOMAIN" q nothing.invalid A @https://localhost:8444/dns-query -p https://localhost:8443/proxy

echo "== q (client) -> OCaml proxy -> doh-server (target)"
check "A" "192.0.2.53" q example.test A @https://localhost:8445/dns-query -p https://localhost:8443/proxy
# The OCaml target again, under a name that the proxy has no route for.
check_fails "q to an unlisted target" "403\|invalid Content-Type" \
  q example.test A @https://127.0.0.1:8444/dns-query -p https://localhost:8443/proxy
check "AAAA" "2001:db8::53" q example.test AAAA @https://localhost:8445/dns-query -p https://localhost:8443/proxy

echo "== OCaml client -> OCaml proxy -> doh-server (target)"
check "A" "NOERROR: 192.0.2.53" client --configs "http://127.0.0.1:$DOH_PORT/.well-known/odohconfigs" \
  --targethost doh-server.test example.test
check "TXT" "oblivious" client --configs "http://127.0.0.1:$DOH_PORT/.well-known/odohconfigs" \
  --targethost doh-server.test --type TXT example.test

echo "== OCaml client -> OCaml proxy -> OCaml target -> doh-server (DoH)"
check "A" "NOERROR: 192.0.2.53" client --configs "http://127.0.0.1:$TARGET_PORT/.well-known/odohconfigs" \
  --targethost ocaml-target.test example.test

echo "== refusals"
check_fails "OCaml proxy refuses an unlisted target" "403" client \
  --configs "http://127.0.0.1:$TARGET_PORT/.well-known/odohconfigs" \
  --targethost elsewhere.test example.test
check_fails "doh-server refuses a query for the OCaml target's key" "401" client \
  --configs "http://127.0.0.1:$TARGET_PORT/.well-known/odohconfigs" \
  --targethost doh-server.test example.test
check_fails "OCaml target refuses a query for doh-server's key" "401" client \
  --configs "http://127.0.0.1:$DOH_PORT/.well-known/odohconfigs" \
  --targethost ocaml-target.test example.test

if [ "$failures" -gt 0 ]; then
  echo "$failures failed; logs in $out"
  exit 1
fi
echo "all passed"
