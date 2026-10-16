#!/usr/bin/env bash
# Builds the multi-threaded engine, runs the sample capture and fails if any fast path
# processed 0 packets or if forwarded + dropped != packets read.
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
make -s BUILD="$tmp" "$tmp/dpi_engine" >"$tmp/build.log" 2>&1 || { cat "$tmp/build.log"; exit 1; }

for cfg in "--lbs 2 --fps 2" "--lbs 2 --fps 4" "--lbs 3 --fps 2"; do
  out=$("$tmp/dpi_engine" test_dpi.pcap "$tmp/out.pcap" --block-app YouTube --block-ip 192.168.1.50 $cfg)
  num() { grep -E "$1" <<<"$out" | awk '{print $(NF-1)}'; }
  total=$(num 'Total Packets'); fwd=$(num 'Forwarded:'); drop=$(num 'Dropped:')
  [ $((fwd + drop)) -eq "$total" ] || { echo "FAIL [$cfg]: forwarded+dropped != total ($fwd+$drop vs $total)"; exit 1; }
  idle=$(num 'FP[0-9]+ processed' | grep -cx 0 || true)
  [ "$idle" -eq 0 ] || { echo "FAIL [$cfg]: $idle fast path(s) processed 0 packets"; exit 1; }
  echo "ok [$cfg]: $total packets, $fwd forwarded, $drop dropped, every FP busy"
done
