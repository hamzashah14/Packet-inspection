#ifndef DPI_SIGNATURE_ENGINE_H
#define DPI_SIGNATURE_ENGINE_H

// Malware signature detection. Four kinds of signature, all loaded from one rules file:
//   payload <name> string:<text>      bytes inside a packet payload (\xNN escapes allowed)
//   payload <name> hex:<hex digits>
//   domain  <name> <domain>           the TLS server name / HTTP Host is this domain or a sub-domain
//   ip      <name> <ip or a.b.c.d/n>  either end of the connection
//   ja3     <name> <32 hex digits>    TLS client fingerprint (see ja3.h)
// Payload patterns are matched with an Aho-Corasick automaton, so cost does not grow with the
// number of signatures. Matching looks at one packet at a time: a pattern split across two TCP
// segments is not found. After finalize() the engine is read-only and safe to share between threads.

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace DPI {

struct SignatureMatch {
    std::string name;
    std::string kind;  // payload, domain, ip, ja3
};

class SignatureEngine {
public:
    bool loadFile(const std::string& path, std::string* err);

    bool addPayload(const std::string& name, const std::vector<uint8_t>& bytes);
    void addDomain(const std::string& name, const std::string& domain);
    bool addIp(const std::string& name, const std::string& ip_or_cidr);  // false if malformed
    bool addJa3(const std::string& name, const std::string& md5);

    void finalize();  // build the automaton; call once after all signatures are added

    bool empty() const { return payload_names_.empty() && domains_.empty() && ips_.empty() && ja3_.empty(); }
    bool hasPayloadSignatures() const { return !payload_names_.empty(); }
    size_t size() const { return payload_names_.size() + domains_.size() + ips_.size() + ja3_.size(); }

    std::optional<SignatureMatch> matchPayload(const uint8_t* data, size_t len) const;
    std::optional<SignatureMatch> matchDomain(const std::string& domain) const;
    // `ip` uses the engine's convention: first octet in the lowest byte (see parseIP in dpi_mt.cpp).
    std::optional<SignatureMatch> matchIp(uint32_t ip) const;
    std::optional<SignatureMatch> matchJa3(const std::string& md5) const;

private:
    struct Node {
        std::array<int32_t, 256> next;
        std::vector<int> out;  // payload signature ids that end here (including via failure links)
        Node() { next.fill(-1); }
    };
    struct Cidr {
        std::string name;
        uint32_t network;  // a.b.c.d as a<<24|b<<16|c<<8|d
        uint32_t mask;
    };

    std::vector<std::vector<uint8_t>> payloads_;
    std::vector<std::string> payload_names_;
    std::vector<Node> nodes_;
    std::vector<std::pair<std::string, std::string>> domains_;  // name, lower-case domain
    std::vector<Cidr> ips_;
    std::vector<std::pair<std::string, std::string>> ja3_;  // name, md5
};

}  // namespace DPI

#endif  // DPI_SIGNATURE_ENGINE_H
