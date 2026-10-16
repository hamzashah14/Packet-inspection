#ifndef DPI_P2P_DETECTOR_H
#define DPI_P2P_DETECTOR_H

// Payload-based BitTorrent detection. Peer-to-peer traffic has no server name to read, so it is
// recognised from the first bytes of a flow instead of from the domain.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>

namespace DPI {

// BitTorrent peer handshake: <19>"BitTorrent protocol" + 8 reserved bytes + info_hash + peer_id.
inline bool isBitTorrentHandshake(const uint8_t* p, size_t len) {
    static constexpr char kProto[] = "BitTorrent protocol";
    return len >= 20 && p[0] == 19 && std::memcmp(p + 1, kProto, 19) == 0;
}

// HTTP tracker announce: GET /announce?info_hash=...
inline bool isTrackerAnnounce(const uint8_t* p, size_t len) {
    std::string_view s(reinterpret_cast<const char*>(p), len);
    return s.rfind("GET ", 0) == 0 && s.find("info_hash=") != std::string_view::npos &&
           s.find("announce") != std::string_view::npos;
}

// Mainline DHT (UDP): a bencoded dictionary with a transaction id, a message type (q, r or e)
// and, for queries and responses, a 20-byte node id.
inline bool isDhtMessage(const uint8_t* p, size_t len) {
    if (len < 20 || p[0] != 'd') return false;
    std::string_view s(reinterpret_cast<const char*>(p), len);
    bool typed = s.find("1:y1:q") != std::string_view::npos || s.find("1:y1:r") != std::string_view::npos ||
                 s.find("1:y1:e") != std::string_view::npos;
    return typed && s.find("2:id20:") != std::string_view::npos;
}

inline bool isBitTorrent(const uint8_t* p, size_t len, uint8_t protocol) {
    if (protocol == 6) return isBitTorrentHandshake(p, len) || isTrackerAnnounce(p, len);
    if (protocol == 17) return isDhtMessage(p, len);
    return false;
}

}  // namespace DPI

#endif  // DPI_P2P_DETECTOR_H
