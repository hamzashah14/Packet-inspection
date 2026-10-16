#!/usr/bin/env python3
"""
Builds tests/features.pcap plus the files the feature test needs:
  tests/features.signatures.txt   signature rules matching the flows below
  tests/features.categories.txt   a custom category
  tests/features.expected         the packet counts the engine must report (from an independent Python model)

Flows (every packet goes client -> server; flows are tracked per direction):
  bt_tcp      BitTorrent handshake, then 20 x 1000-byte data packets, 10 packets/second
  bt_dht      three DHT queries over UDP
  eicar       HTTP-like payload carrying the EICAR antivirus test string
  c2_domain   TLS ClientHello for a server name on a domain signature
  bad_ip      traffic to an address inside an ip signature range
  ja3         TLS ClientHello whose JA3 hash is on a ja3 signature (includes GREASE values)
  ads         TLS ClientHello for ads.doubleclick.net (built-in "ads" category)
  work        TLS ClientHello for git.corp.example (custom "work" category)
  control     TLS ClientHello for example.org (must always pass)
"""
import hashlib
import os
import random
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from generate_test_pcap import (create_dns_query, create_ethernet_header, create_ip_header,  # noqa: E402
                                create_tcp_header, create_udp_header)

HERE = os.path.dirname(os.path.abspath(__file__))
SYN, ACK, PSH_ACK = 0x02, 0x10, 0x18
EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

random.seed(1)  # the shared helpers randomise IP ids; keep the output reproducible
packets = []  # (timestamp seconds, bytes, flow name)


def eth(): return create_ethernet_header("aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02")


def tcp_packet(t, flow, src, sport, dst, dport, flags, payload=b""):
    tcp = create_tcp_header(sport, dport, 1000, 0, flags)
    ip = create_ip_header(src, dst, 6, len(tcp) + len(payload))
    packets.append((t, eth() + ip + tcp + payload, flow))


def udp_packet(t, flow, src, sport, dst, dport, payload):
    udp = create_udp_header(sport, dport, len(payload))
    ip = create_ip_header(src, dst, 17, len(udp) + len(payload))
    packets.append((t, eth() + ip + udp + payload, flow))


def client_hello(sni, ciphers, groups, point_formats, extra_ext_order=None):
    """TLS ClientHello. Returns (record bytes, JA3 text)."""
    def ext(t, body): return struct.pack(">HH", t, len(body)) + body
    sni_b = sni.encode()
    sni_entry = struct.pack(">BH", 0, len(sni_b)) + sni_b
    exts = [
        (0x2A2A, b""),                                                          # GREASE
        (0, struct.pack(">H", len(sni_entry)) + sni_entry),                    # server_name
        (10, struct.pack(">H", len(groups) * 2) + b"".join(struct.pack(">H", g) for g in groups)),
        (11, bytes([len(point_formats)]) + bytes(point_formats)),
        (43, bytes([2]) + struct.pack(">H", 0x0304)),                           # supported_versions
    ]
    body = struct.pack(">H", 0x0303) + bytes(32) + b"\x00"
    body += struct.pack(">H", len(ciphers) * 2) + b"".join(struct.pack(">H", c) for c in ciphers)
    body += b"\x01\x00"
    ext_bytes = b"".join(ext(t, b) for t, b in exts)
    body += struct.pack(">H", len(ext_bytes)) + ext_bytes
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    record = b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs

    grease = lambda v: (v & 0x0F0F) == 0x0A0A  # noqa: E731
    ja3 = ",".join([
        str(0x0303),
        "-".join(str(c) for c in ciphers if not grease(c)),
        "-".join(str(t) for t, _ in exts if not grease(t)),
        "-".join(str(g) for g in groups if not grease(g)),
        "-".join(str(p) for p in point_formats),
    ])
    return record, ja3


PLAIN_CIPHERS = [0x1301, 0x1302]
PLAIN_GROUPS = [29, 23]


def tls_flow(name, t0, src, sport, dst, sni, follow=2, ciphers=PLAIN_CIPHERS, groups=PLAIN_GROUPS):
    hello, ja3 = client_hello(sni, ciphers, groups, [0])
    tcp_packet(t0, name, src, sport, dst, 443, SYN)
    tcp_packet(t0 + 0.01, name, src, sport, dst, 443, PSH_ACK, hello)
    for i in range(follow):
        tcp_packet(t0 + 0.02 + 0.01 * i, name, src, sport, dst, 443, PSH_ACK, b"\x17\x03\x03\x00\x10" + bytes(16))
    return ja3


# --- flows ---------------------------------------------------------------------------------
handshake = bytes([19]) + b"BitTorrent protocol" + bytes(8) + bytes(range(20)) + bytes(range(20, 40))
tcp_packet(1.00, "bt_tcp", "10.0.0.10", 50001, "198.51.100.10", 6881, SYN)
tcp_packet(1.01, "bt_tcp", "10.0.0.10", 50001, "198.51.100.10", 6881, PSH_ACK, handshake)
for i in range(20):
    tcp_packet(1.1 + 0.1 * i, "bt_tcp", "10.0.0.10", 50001, "198.51.100.10", 6881, PSH_ACK, bytes([i]) * 1000)

dht = b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe"
for i in range(3):
    udp_packet(1.0 + 0.2 * i, "bt_dht", "10.0.0.11", 50002, "203.0.113.5", 6881, dht)

tcp_packet(2.00, "eicar", "10.0.0.12", 50003, "198.51.100.20", 8080, SYN)
tcp_packet(2.01, "eicar", "10.0.0.12", 50003, "198.51.100.20", 8080, PSH_ACK,
           b"HTTP/1.1 200 OK\r\n\r\n" + EICAR.encode())
tcp_packet(2.02, "eicar", "10.0.0.12", 50003, "198.51.100.20", 8080, PSH_ACK, b"more data")
tcp_packet(2.03, "eicar", "10.0.0.12", 50003, "198.51.100.20", 8080, PSH_ACK, b"more data")

tls_flow("c2_domain", 3.00, "10.0.0.13", 50004, "198.51.100.30", "update.evil-example.test")

tcp_packet(4.00, "bad_ip", "10.0.0.14", 50005, "203.0.113.66", 4444, SYN)
tcp_packet(4.01, "bad_ip", "10.0.0.14", 50005, "203.0.113.66", 4444, PSH_ACK, b"hello")
tcp_packet(4.02, "bad_ip", "10.0.0.14", 50005, "203.0.113.66", 4444, PSH_ACK, b"hello")

ja3_text = tls_flow("ja3", 5.00, "10.0.0.15", 50006, "198.51.100.40", "ja3.example.org", follow=1,
                    ciphers=[0x0A0A, 0x1301, 0x1302, 0xC02B, 0xC02F], groups=[0x3A3A, 29, 23, 24])
ja3_hash = hashlib.md5(ja3_text.encode()).hexdigest()

tls_flow("ads", 6.00, "10.0.0.16", 50007, "198.51.100.50", "ads.doubleclick.net")
tls_flow("work", 7.00, "10.0.0.17", 50008, "198.51.100.60", "git.corp.example", follow=1)
tls_flow("control", 8.00, "10.0.0.18", 50009, "198.51.100.70", "example.org")
udp_packet(8.5, "control", "10.0.0.18", 50010, "198.51.100.71", 53, create_dns_query("example.org"))

packets.sort(key=lambda p: p[0])

# --- write files -----------------------------------------------------------------------------
with open(os.path.join(HERE, "features.pcap"), "wb") as f:
    f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for t, data, _ in packets:
        sec, usec = int(t), int(round((t - int(t)) * 1_000_000))
        f.write(struct.pack("<IIII", 1_700_000_000 + sec, usec, len(data), len(data)) + data)

with open(os.path.join(HERE, "features.signatures.txt"), "w") as f:
    f.write("# Generated by make_feature_pcap.py\n")
    f.write("payload EICAR-Test string:" + EICAR.replace("\\", "\\\\") + "\n")
    f.write("domain  C2-Domain evil-example.test\n")
    f.write("ip      Bad-Range 203.0.113.64/27\n")
    f.write(f"ja3     Test-Client {ja3_hash}\n")
with open(os.path.join(HERE, "features.categories.txt"), "w") as f:
    f.write("# custom category\nwork: corp.example\n")

# --- expected counts: independent model of the engine's rules ---------------------------------
by_flow = {}
for t, data, flow in packets:
    by_flow.setdefault(flow, []).append((t, data))
total = len(packets)


def first_index(flow, pred):
    for i, (_, data) in enumerate(by_flow[flow]):
        if pred(data):
            return i
    raise AssertionError(flow)


def dropped_from(flow, index):  # packets from `index` on are dropped
    return len(by_flow[flow]) - index


sig_drop = (dropped_from("eicar", first_index("eicar", lambda d: EICAR.encode() in d))
            + dropped_from("c2_domain", first_index("c2_domain", lambda d: b"evil-example.test" in d))
            + dropped_from("bad_ip", 0)
            + dropped_from("ja3", first_index("ja3", lambda d: b"ja3.example.org" in d)))
ads_drop = dropped_from("ads", first_index("ads", lambda d: b"doubleclick" in d))
work_drop = dropped_from("work", first_index("work", lambda d: b"corp.example" in d))


def throttled(rate_bytes_per_s):
    """Token bucket per flow, packet timestamps, applied from the packet that classifies the flow."""
    cap = max(rate_bytes_per_s, 1500.0)
    pkts = by_flow["bt_tcp"][1:]  # the SYN is not yet recognised as BitTorrent
    tokens, last, drops = None, None, 0
    for t, data in pkts:
        if tokens is None:
            tokens, last = cap, t
        else:
            tokens = min(cap, tokens + rate_bytes_per_s * max(0.0, t - last))
            last = max(last, t)
        if tokens >= len(data):
            tokens -= len(data)
        else:
            drops += 1
    return drops


bt_syn = 1
bt_tcp_total = len(by_flow["bt_tcp"])
bt_block = (bt_tcp_total - bt_syn) + len(by_flow["bt_dht"])

with open(os.path.join(HERE, "features.expected"), "w") as f:
    f.write(f"total={total}\n")
    f.write(f"signature_drops={sig_drop}\n")
    f.write(f"ads_category_drops={ads_drop}\n")
    f.write(f"work_category_drops={work_drop}\n")
    f.write(f"throttle_2kb_drops={throttled(2048)}\n")
    f.write(f"bittorrent_rule_drops={bt_block}\n")
    f.write(f"bittorrent_packets={bt_tcp_total - bt_syn + len(by_flow['bt_dht'])}\n")
    f.write(f"ja3_hash={ja3_hash}\n")

# The same traffic as loopback captures (DLT_NULL: 4-byte family in host order, DLT_LOOP: network order),
# to test the libpcap path's link-layer conversion without needing a live interface.
for name, linktype, fmt in (("features_null.pcap", 0, "<I"), ("features_loop.pcap", 108, ">I")):
    with open(os.path.join(HERE, name), "wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        for t, data, _ in packets:
            frame = struct.pack(fmt, 2) + data[14:]  # AF_INET + the IP packet
            sec, usec = int(t), int(round((t - int(t)) * 1_000_000))
            f.write(struct.pack("<IIII", 1_700_000_000 + sec, usec, len(frame), len(frame)) + frame)
with open(os.path.join(HERE, "features_unsupported.pcap"), "wb") as f:  # Linux "cooked" capture, not supported
    f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 113))

# One flow on a signature IP that goes silent for 20 minutes and then resumes: the engine must have
# forgotten it in between, so it is detected (and counted) as a new flow the second time.
packets.clear()
for t in (1.0, 1.1, 1.2, 1200.0, 1200.1):
    tcp_packet(t, "idle", "10.0.0.14", 50005, "203.0.113.66", 4444, PSH_ACK, b"hello")
tcp_packet(1201.0, "idle", "10.0.0.99", 50099, "198.51.100.99", 4445, PSH_ACK, b"later")
tcp_packet(1900.0, "idle", "10.0.0.98", 50098, "198.51.100.98", 4446, PSH_ACK, b"much later")  # time moves on: sweeps run
with open(os.path.join(HERE, "features_idle.pcap"), "wb") as f:
    f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for t, data, _ in packets:
        sec, usec = int(t), int(round((t - int(t)) * 1_000_000))
        f.write(struct.pack("<IIII", 1_700_000_000 + sec, usec, len(data), len(data)) + data)

print(f"wrote features.pcap ({total} packets), expected counts and rule files in {HERE}")
