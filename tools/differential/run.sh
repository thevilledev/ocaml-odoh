#!/bin/sh
# Build the peers and run the differential driver against them.
#
#   tools/differential/run.sh [--record test/vectors/differential]
#
# The Go peer needs Go, and network access the first time, for its modules.
# The Rust peer needs Docker, and network access the first time, for its base
# image and crates; afterwards it runs without a network. A peer whose tools
# are missing is skipped, unless --record asks for a corpus: a recorded corpus
# that silently lacks a peer would be worse than none.
set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)
out=${DIFFERENTIAL_BUILD_DIR:-$root/_build/differential}
mkdir -p "$out"

recording=false
for arg in "$@"; do
  [ "$arg" = "--record" ] && recording=true
done

if command -v go >/dev/null 2>&1; then
  (cd "$root/tools/differential/go" && go build -o "$out/go-peer" .)
  set -- "$@" --peer "go=$out/go-peer"
elif $recording; then
  echo "recording needs the Go peer, and go is not installed" >&2
  exit 3
fi

if docker info >/dev/null 2>&1; then
  DOCKER_BUILDKIT=1 docker build -q -t ocaml-odoh/rust-peer \
    "$root/tools/differential/rust" >/dev/null
  set -- "$@" --peer "rust=$root/tools/differential/rust/peer.sh"
elif $recording; then
  echo "recording needs the Rust peer, and docker is not running" >&2
  exit 3
fi

(cd "$root" && opam exec -- dune build ./tools/differential/differential.exe)
cd "$root"
exec "$root/_build/default/tools/differential/differential.exe" "$@"
