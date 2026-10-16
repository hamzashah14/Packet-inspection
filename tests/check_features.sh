#!/usr/bin/env bash
# End-to-end checks of signatures, content categories, P2P detection, throttling and the libpcap path.
# Uses tests/features.pcap, built by tests/make_feature_pcap.py together with the expected counts.
set -uo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
failures=0

make -s BUILD="$tmp" "$tmp/dpi_engine" >"$tmp/build.log" 2>&1 || { cat "$tmp/build.log"; echo "FAIL: build"; exit 1; }
bin="$tmp/dpi_engine"

exp() { grep "^$1=" tests/features.expected | cut -d= -f2; }
num() { grep -E "$1" <<<"$out" | head -1 | awk '{print $(NF-1)}'; }
check() {  # check <what> <actual> <expected>
  if [ "$2" = "$3" ]; then echo "ok   $1 ($2)"; else echo "FAIL $1: got $2, expected $3"; failures=$((failures + 1)); fi
}
run() { out=$("$bin" tests/features.pcap "$tmp/out.pcap" "$@" 2>&1); }
total=$(exp total)

run
check "baseline drops nothing" "$(num 'Dropped:')" 0
check "baseline forwards everything" "$(num 'Forwarded:')" "$total"
check "BitTorrent recognised from payload (TCP handshake + UDP DHT)" \
      "$(grep -E '^║ BitTorrent' <<<"$out" | awk '{print $3}')" "$(exp bittorrent_packets)"

run --signatures tests/features.signatures.txt
check "signatures: dropped" "$(num 'by signature:')" "$(exp signature_drops)"
check "signatures: forwarded + dropped = total" "$(( $(num 'Forwarded:') + $(num 'Dropped:') ))" "$total"
check "signature kinds detected (payload, domain, ip, ja3)" "$(grep -c '  - signature: ' <<<"$out")" 4
check "JA3 computed in C++ equals the Python hash" "$(grep -c 'signature: ja3 Test-Client' <<<"$out")" 1

run --signatures tests/features.signatures.txt --lbs 1 --fps 1
check "signatures: same result with 1 LB x 1 FP" "$(num 'by signature:')" "$(exp signature_drops)"
run --signatures tests/features.signatures.txt --lbs 3 --fps 2
check "signatures: same result with 3 LBs x 2 FPs" "$(num 'by signature:')" "$(exp signature_drops)"

run --block-category ads
check "category ads: dropped" "$(num 'by category:')" "$(exp ads_category_drops)"
run --categories tests/features.categories.txt --block-category work
check "custom category: dropped" "$(num 'by category:')" "$(exp work_category_drops)"

run --block-app BitTorrent
check "block-app BitTorrent: dropped by rule" "$(num 'by rule:')" "$(exp bittorrent_rule_drops)"
run --block-app bittorrent
check "block-app is case-insensitive" "$(num 'by rule:')" "$(exp bittorrent_rule_drops)"

run --throttle-p2p 2KB/s
check "throttle 2KB/s: matches the token-bucket model" "$(num 'by throttle:')" "$(exp throttle_2kb_drops)"
check "throttle drops are counted in Dropped" "$(num 'Dropped:')" "$(exp throttle_2kb_drops)"
run --throttle-app BitTorrent 100MB/s
check "throttle far above the offered load drops nothing" "$(num 'by throttle:')" 0

run --signatures tests/features.signatures.txt --categories tests/features.categories.txt \
    --block-category ads --block-category work --throttle-p2p 2KB/s
check "combined: signature drops" "$(num 'by signature:')" "$(exp signature_drops)"
check "combined: category drops" "$(num 'by category:')" "$(( $(exp ads_category_drops) + $(exp work_category_drops) ))"
check "combined: throttle drops" "$(num 'by throttle:')" "$(exp throttle_2kb_drops)"
check "combined: forwarded + dropped = total" "$(( $(num 'Forwarded:') + $(num 'Dropped:') ))" "$total"

run --show-ja3
check "--show-ja3 lists the fingerprint" "$(grep -c "$(exp ja3_hash)" <<<"$out")" 1

# Idle flows are forgotten: the same 5-tuple after 20 quiet minutes is detected as a new flow
out=$("$bin" tests/features_idle.pcap "$tmp/out_idle.pcap" --signatures tests/features.signatures.txt 2>&1)
check "idle flow expiry: flow detected again after 20 minutes of silence" \
      "$(grep -E 'signature: ip Bad-Range' <<<"$out" | grep -oE '\([0-9]+ flows?\)')" "(2 flows)"
check "idle flow expiry: every packet of those flows dropped" "$(num 'by signature:')" 5
out=$("$bin" tests/features_idle.pcap "$tmp/out_idle.pcap" --signatures tests/features.signatures.txt --lbs 1 --fps 1 2>&1)
check "idle flow expiry with a single fast path (exercises the sweep)" \
      "$(grep -E 'signature: ip Bad-Range' <<<"$out" | grep -oE '\([0-9]+ flows?\)')" "(2 flows)"

# Bad input must fail with a message, not be ignored
for bad in "--block-app NoSuchApp" "--block-category nope" "--throttle-p2p fast" "--bogus" "--signatures /nonexistent"; do
  # shellcheck disable=SC2086
  if msg=$("$bin" tests/features.pcap "$tmp/out.pcap" $bad 2>&1); then
    echo "FAIL bad option accepted: $bad"; failures=$((failures + 1))
  else
    echo "ok   rejected: $bad"
  fi
done
printf 'payload Broken string:\\q\n' > "$tmp/bad.txt"
if "$bin" tests/features.pcap "$tmp/out.pcap" --signatures "$tmp/bad.txt" >"$tmp/msg" 2>&1 || ! grep -q 'bad.txt:1' "$tmp/msg"; then
  echo "FAIL malformed rules file should be rejected with file:line"; failures=$((failures + 1))
else
  echo "ok   malformed rules file rejected with file:line"
fi

# libpcap path (skipped when libpcap headers are missing)
if make -s BUILD="$tmp" dpi_engine_live >/dev/null 2>&1; then
  live="$tmp/dpi_engine_live"
  out=$("$live" --libpcap-file tests/features.pcap "$tmp/out_pcap.pcap" --signatures tests/features.signatures.txt 2>&1)
  check "libpcap path: forwarded + dropped = total" "$(( $(num 'Forwarded:') + $(num 'Dropped:') ))" "$total"
  check "libpcap path: same signature drops as the file reader" "$(num 'by signature:')" "$(exp signature_drops)"
  out=$("$live" --libpcap-file tests/features.pcap "$tmp/out_bpf.pcap" --bpf "udp" 2>&1)
  check "libpcap BPF filter 'udp' keeps only UDP packets (3 DHT + 1 DNS)" "$(num 'Total Packets:')" 4
  out=$("$live" --libpcap-file tests/features.pcap "$tmp/out_n.pcap" --count 10 2>&1)
  check "--count 10 stops the capture after 10 packets" "$(num 'Total Packets:')" 10
  for cap in features_null features_loop; do
    out=$("$live" --libpcap-file "tests/$cap.pcap" "$tmp/out_$cap.pcap" --signatures tests/features.signatures.txt 2>&1)
    check "loopback capture $cap: all packets converted" "$(num 'Total Packets:')" "$total"
    check "loopback capture $cap: same signature drops" "$(num 'by signature:')" "$(exp signature_drops)"
  done
  if msg=$("$live" --libpcap-file tests/features_unsupported.pcap "$tmp/x.pcap" 2>&1); then
    echo "FAIL unsupported link type should be rejected"; failures=$((failures + 1))
  elif grep -q 'unsupported link type 113' <<<"$msg"; then echo "ok   unsupported link type rejected with a clear message"
  else echo "FAIL unclear message for unsupported link type: $msg"; failures=$((failures + 1)); fi
  if msg=$("$live" --iface lo0 --count 1 --duration 1 "$tmp/live.pcap" 2>&1); then
    echo "ok   live capture on lo0 worked (this user may capture)"
  elif grep -qiE 'permission|privilege|no such device|not exist' <<<"$msg"; then
    echo "ok   live capture error is explained: $(grep -m1 -iE 'permission|privilege|no such' <<<"$msg" | cut -c1-110)"
  else
    echo "FAIL live capture failed without a clear reason: $msg"; failures=$((failures + 1))
  fi
else
  echo "skip libpcap checks (libpcap headers not available)"
fi

[ "$failures" -eq 0 ] && echo "all feature checks passed" || { echo "$failures check(s) failed"; exit 1; }
