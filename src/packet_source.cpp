#include "packet_source.h"

#ifdef HAVE_PCAP

#include <pcap.h>

#include <atomic>
#include <chrono>
#include <cstring>

namespace DPI {

namespace {

std::atomic<bool> g_stop{false};

double nowSeconds() {
    using namespace std::chrono;
    return duration<double>(steady_clock::now().time_since_epoch()).count();
}

constexpr int kDltEthernet = 1;  // DLT_EN10MB
constexpr int kDltNull = 0;      // BSD loopback: 4-byte address family in host byte order
constexpr int kDltLoop = 108;    // OpenBSD loopback: same, network byte order
constexpr uint32_t kAfInet = 2;

std::string permissionHint() {
    return " (capturing needs privileges: run with sudo, on macOS install Wireshark's ChmodBPF to allow your user, "
           "on Linux run `sudo setcap cap_net_raw,cap_net_admin=eip ./dpi_engine`)";
}

}  // namespace

void requestLiveStop() { g_stop = true; }

std::vector<std::string> listInterfaces(std::string* err) {
    std::vector<std::string> out;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t* devs = nullptr;
    if (pcap_findalldevs(&devs, errbuf) != 0) {
        if (err) *err = errbuf;
        return out;
    }
    for (pcap_if_t* d = devs; d; d = d->next) {
        std::string line = d->name;
        if (d->description) line += std::string("  (") + d->description + ")";
        out.push_back(line);
    }
    pcap_freealldevs(devs);
    return out;
}

bool LiveSource::open(const LiveOptions& opts, std::string* err) {
    opts_ = opts;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t* h = nullptr;

    if (!opts.offline_file.empty()) {
        h = pcap_open_offline(opts.offline_file.c_str(), errbuf);
        if (!h) {
            if (err) *err = errbuf;
            return false;
        }
    } else {
        h = pcap_create(opts.iface.c_str(), errbuf);
        if (!h) {
            if (err) *err = errbuf;
            return false;
        }
        pcap_set_snaplen(h, opts.snaplen);
        pcap_set_promisc(h, opts.promiscuous ? 1 : 0);
        pcap_set_timeout(h, opts.poll_ms);
        pcap_set_immediate_mode(h, 1);  // deliver packets as they arrive instead of in batches
        int rc = pcap_activate(h);
        if (rc < 0) {
            std::string msg = std::string(pcap_statustostr(rc)) + ": " + opts.iface;
            const char* detail = pcap_geterr(h);
            if (detail && *detail) msg += std::string(" - ") + detail;
            if (rc == PCAP_ERROR_PERM_DENIED) msg += permissionHint();
            if (err) *err = msg;
            pcap_close(h);
            return false;
        }
        if (rc > 0) std::fprintf(stderr, "[Capture] warning: %s\n", pcap_statustostr(rc));
    }

    datalink_ = pcap_datalink(h);
    if (datalink_ != kDltEthernet && datalink_ != kDltNull && datalink_ != kDltLoop) {
        if (err) *err = "unsupported link type " + std::to_string(datalink_) + " (need Ethernet or loopback)";
        pcap_close(h);
        return false;
    }

    if (!opts.bpf_filter.empty()) {
        bpf_program prog;
        if (pcap_compile(h, &prog, opts.bpf_filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) != 0 ||
            pcap_setfilter(h, &prog) != 0) {
            if (err) *err = "bad filter \"" + opts.bpf_filter + "\": " + pcap_geterr(h);
            pcap_close(h);
            return false;
        }
        pcap_freecode(&prog);
    }

    handle_ = h;
    // Packets are handed to the engine as Ethernet frames, so the output file is always Ethernet.
    header_ = {0xa1b2c3d4, 2, 4, 0, 0, static_cast<uint32_t>(opts.snaplen), 1};
    started_ = nowSeconds();
    g_stop = false;
    return true;
}

bool LiveSource::readNextPacket(PacketAnalyzer::RawPacket& out) {
    pcap_t* h = static_cast<pcap_t*>(handle_);
    if (!h) return false;
    for (;;) {
        if (g_stop) return false;
        if (opts_.max_packets && delivered_ >= opts_.max_packets) return false;
        if (opts_.max_seconds > 0 && nowSeconds() - started_ >= opts_.max_seconds) return false;

        pcap_pkthdr* hdr = nullptr;
        const u_char* data = nullptr;
        int rc = pcap_next_ex(h, &hdr, &data);
        if (rc == 0) continue;  // timeout on a quiet network: loop to re-check stop and limits
        if (rc == PCAP_ERROR_BREAK) return false;
        if (rc < 0) {
            if (rc == PCAP_ERROR) error_ = pcap_geterr(h);
            return false;
        }

        size_t len = hdr->caplen;
        out.data.clear();
        if (datalink_ == kDltEthernet) {
            out.data.assign(data, data + len);
        } else {
            // Loopback: swap the 4-byte family header for a 14-byte Ethernet header (IPv4 only).
            if (len < 4) continue;
            uint32_t family;
            std::memcpy(&family, data, 4);
            if (datalink_ == kDltLoop) family = __builtin_bswap32(family);
            if (family != kAfInet) continue;
            static const uint8_t eth[14] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x00};
            out.data.assign(eth, eth + 14);
            out.data.insert(out.data.end(), data + 4, data + len);
        }
        out.header.ts_sec = static_cast<uint32_t>(hdr->ts.tv_sec);
        out.header.ts_usec = static_cast<uint32_t>(hdr->ts.tv_usec);
        out.header.incl_len = static_cast<uint32_t>(out.data.size());
        out.header.orig_len = static_cast<uint32_t>(out.data.size() + (hdr->len - hdr->caplen));
        delivered_++;
        return true;
    }
}

bool LiveSource::kernelStats(uint64_t* received, uint64_t* dropped) const {
    pcap_t* h = static_cast<pcap_t*>(handle_);
    if (!h || !opts_.offline_file.empty()) return false;
    pcap_stat st;
    if (pcap_stats(h, &st) != 0) return false;
    *received = st.ps_recv;
    *dropped = st.ps_drop;
    return true;
}

std::string LiveSource::describe() const {
    return opts_.offline_file.empty() ? "libpcap live capture on " + opts_.iface
                                      : "libpcap reading " + opts_.offline_file;
}

void LiveSource::close() {
    if (handle_) {
        pcap_close(static_cast<pcap_t*>(handle_));
        handle_ = nullptr;
    }
}

}  // namespace DPI

#endif  // HAVE_PCAP
