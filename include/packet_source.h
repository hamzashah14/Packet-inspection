#ifndef DPI_PACKET_SOURCE_H
#define DPI_PACKET_SOURCE_H

// Where packets come from: a PCAP file (always available) or libpcap (live capture from a network
// interface, built with -DHAVE_PCAP and linked with -lpcap).

#include <memory>
#include <string>
#include <vector>

#include "pcap_reader.h"

namespace DPI {

class PacketSource {
public:
    virtual ~PacketSource() = default;
    // Next packet, Ethernet framed. Returns false at the end of the file or when a live capture stops.
    virtual bool readNextPacket(PacketAnalyzer::RawPacket& packet) = 0;
    virtual const PacketAnalyzer::PcapGlobalHeader& globalHeader() const = 0;
    virtual std::string describe() const = 0;
    virtual void close() {}
};

class FileSource : public PacketSource {
public:
    bool open(const std::string& path) { return reader_.open(path); }
    bool readNextPacket(PacketAnalyzer::RawPacket& p) override { return reader_.readNextPacket(p); }
    const PacketAnalyzer::PcapGlobalHeader& globalHeader() const override { return reader_.getGlobalHeader(); }
    std::string describe() const override { return "file"; }
    void close() override { reader_.close(); }

private:
    PacketAnalyzer::PcapReader reader_;
};

#ifdef HAVE_PCAP

struct LiveOptions {
    std::string iface;         // interface to capture from, e.g. en0 or eth0
    std::string offline_file;  // read this file through libpcap instead (tests the libpcap path without root)
    std::string bpf_filter;    // optional, e.g. "tcp port 443"
    int snaplen = 65535;
    bool promiscuous = true;
    int poll_ms = 200;         // how often a quiet capture checks for Ctrl-C and limits
    uint64_t max_packets = 0;  // stop after this many packets (0 = no limit)
    double max_seconds = 0;    // stop after this long (0 = no limit)
};

class LiveSource : public PacketSource {
public:
    ~LiveSource() override { close(); }
    bool open(const LiveOptions& opts, std::string* err);
    bool readNextPacket(PacketAnalyzer::RawPacket& p) override;
    const PacketAnalyzer::PcapGlobalHeader& globalHeader() const override { return header_; }
    std::string describe() const override;
    void close() override;

    // Packets libpcap saw / the kernel dropped because we were too slow (live capture only).
    bool kernelStats(uint64_t* received, uint64_t* dropped) const;
    std::string lastError() const { return error_; }

private:
    void* handle_ = nullptr;  // pcap_t*
    LiveOptions opts_;
    PacketAnalyzer::PcapGlobalHeader header_{};
    int datalink_ = 1;
    uint64_t delivered_ = 0;
    double started_ = 0;
    std::string error_;
};

// Ctrl-C support: the signal handler calls this, readNextPacket() then returns false.
void requestLiveStop();
std::vector<std::string> listInterfaces(std::string* err);

#endif  // HAVE_PCAP

}  // namespace DPI

#endif  // DPI_PACKET_SOURCE_H
