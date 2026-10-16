#include "ja3.h"

#include <cstring>
#include <vector>

namespace DPI {

// ---------------------------------------------------------------------------------------------
// MD5 (RFC 1321)
// ---------------------------------------------------------------------------------------------
namespace {

inline uint32_t rol(uint32_t x, int c) { return (x << c) | (x >> (32 - c)); }

const uint32_t K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};
const int S[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9,  14, 20, 5, 9,
                   14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                   4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

void md5Block(uint32_t state[4], const uint8_t* block) {
    uint32_t m[16];
    for (int i = 0; i < 16; i++)
        m[i] = block[i * 4] | (block[i * 4 + 1] << 8) | (block[i * 4 + 2] << 16) | (uint32_t(block[i * 4 + 3]) << 24);
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    for (int i = 0; i < 64; i++) {
        uint32_t f;
        int g;
        if (i < 16) { f = (b & c) | (~b & d); g = i; }
        else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) % 16; }
        else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) % 16; }
        else { f = c ^ (b | ~d); g = (7 * i) % 16; }
        uint32_t tmp = d;
        d = c;
        c = b;
        b = b + rol(a + f + K[i] + m[g], S[i]);
        a = tmp;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

}  // namespace

std::string md5Hex(const uint8_t* data, size_t len) {
    uint32_t state[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
    size_t full = len / 64;
    for (size_t i = 0; i < full; i++) md5Block(state, data + i * 64);

    uint8_t tail[128] = {0};
    size_t rem = len - full * 64;
    if (rem) std::memcpy(tail, data + full * 64, rem);
    tail[rem] = 0x80;
    size_t tail_len = (rem < 56) ? 64 : 128;
    uint64_t bits = static_cast<uint64_t>(len) * 8;
    for (int i = 0; i < 8; i++) tail[tail_len - 8 + i] = static_cast<uint8_t>(bits >> (8 * i));
    for (size_t off = 0; off < tail_len; off += 64) md5Block(state, tail + off);

    static const char* hex = "0123456789abcdef";
    std::string out;
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++) {
            uint8_t byte = static_cast<uint8_t>(state[i] >> (8 * j));
            out += hex[byte >> 4];
            out += hex[byte & 0x0f];
        }
    return out;
}

// ---------------------------------------------------------------------------------------------
// JA3
// ---------------------------------------------------------------------------------------------
namespace {

inline bool isGrease(uint16_t v) { return (v & 0x0f0f) == 0x0a0a; }

struct Reader {
    const uint8_t* p;
    size_t len;
    size_t pos = 0;
    bool ok = true;
    bool need(size_t n) {
        if (!ok || pos + n > len) ok = false;
        return ok;
    }
    uint8_t u8() { return need(1) ? p[pos++] : 0; }
    uint16_t u16() {
        if (!need(2)) return 0;
        uint16_t v = (p[pos] << 8) | p[pos + 1];
        pos += 2;
        return v;
    }
    void skip(size_t n) {
        if (need(n)) pos += n;
    }
};

void append(std::string& out, uint16_t v, bool& first) {
    if (!first) out += '-';
    out += std::to_string(v);
    first = false;
}

}  // namespace

std::optional<Ja3> computeJa3(const uint8_t* payload, size_t len) {
    Reader r{payload, len};
    if (r.u8() != 0x16) return std::nullopt;  // TLS handshake record
    r.skip(2);                                // record version
    uint16_t record_len = r.u16();
    if (!r.ok || r.pos + record_len > len) return std::nullopt;  // ClientHello must be in this packet
    if (r.u8() != 0x01) return std::nullopt;                      // ClientHello
    r.skip(3);                                                    // handshake length
    uint16_t version = r.u16();
    r.skip(32);                                                   // random
    r.skip(r.u8());                                               // session id

    uint16_t cipher_bytes = r.u16();
    if (!r.ok || (cipher_bytes & 1) || r.pos + cipher_bytes > len) return std::nullopt;
    std::string ciphers;
    bool first = true;
    for (uint16_t i = 0; i < cipher_bytes; i += 2) {
        uint16_t c = r.u16();
        if (!isGrease(c)) append(ciphers, c, first);
    }
    r.skip(r.u8());  // compression methods

    std::string extensions, curves, formats;
    bool first_ext = true;
    if (r.pos < len) {
        uint16_t ext_total = r.u16();
        size_t end = r.pos + ext_total;
        if (!r.ok || end > len) return std::nullopt;
        while (r.ok && r.pos + 4 <= end) {
            uint16_t type = r.u16();
            uint16_t size = r.u16();
            size_t body = r.pos;
            if (body + size > end) return std::nullopt;
            if (!isGrease(type)) append(extensions, type, first_ext);
            if (type == 10 && size >= 2) {  // supported_groups
                Reader e{payload + body, size};
                uint16_t list = e.u16();
                bool f = true;
                for (uint16_t i = 0; e.ok && i + 1 < list; i += 2) {
                    uint16_t g = e.u16();
                    if (!isGrease(g)) append(curves, g, f);
                }
            } else if (type == 11 && size >= 1) {  // ec_point_formats
                Reader e{payload + body, size};
                uint8_t list = e.u8();
                bool f = true;
                for (uint8_t i = 0; e.ok && i < list; i++) append(formats, e.u8(), f);
            }
            r.pos = body + size;
        }
    }
    if (!r.ok) return std::nullopt;

    Ja3 out;
    out.text = std::to_string(version) + "," + ciphers + "," + extensions + "," + curves + "," + formats;
    out.hash = md5Hex(reinterpret_cast<const uint8_t*>(out.text.data()), out.text.size());
    return out;
}

}  // namespace DPI
