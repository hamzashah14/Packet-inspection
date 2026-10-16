#ifndef DPI_JA3_H
#define DPI_JA3_H

// JA3 TLS client fingerprint: an MD5 of the ClientHello's version, cipher suites, extensions,
// elliptic curves and point formats. The same client software always produces the same hash, so
// known malware families can be recognised even when everything else is encrypted.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace DPI {

std::string md5Hex(const uint8_t* data, size_t len);

struct Ja3 {
    std::string text;  // e.g. "771,4865-4866,0-43,,"
    std::string hash;  // MD5 of text, lower-case hex
};

// `payload` is the TCP payload of the first packet of a TLS connection. Returns nothing unless it
// holds a complete ClientHello.
std::optional<Ja3> computeJa3(const uint8_t* payload, size_t len);

}  // namespace DPI

#endif  // DPI_JA3_H
