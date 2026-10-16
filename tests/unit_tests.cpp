// Unit tests for the building blocks: MD5/JA3, signatures, content filter, P2P detection, token bucket.
// Build and run with `make unit-test`.
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "content_filter.h"
#include "ja3.h"
#include "p2p_detector.h"
#include "signature_engine.h"
#include "token_bucket.h"

using namespace DPI;

static int failures = 0;
#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);            \
            failures++;                                                            \
        }                                                                          \
    } while (0)

static std::string md5(const std::string& s) { return md5Hex(reinterpret_cast<const uint8_t*>(s.data()), s.size()); }
static const uint8_t* B(const std::string& s) { return reinterpret_cast<const uint8_t*>(s.data()); }
static uint32_t ipv4(int a, int b, int c, int d) { return a | (b << 8) | (c << 16) | (uint32_t(d) << 24); }  // engine order

int main() {
    // MD5: RFC 1321 test suite plus padding edge cases (55, 56, 64 bytes)
    CHECK(md5("") == "d41d8cd98f00b204e9800998ecf8427e");
    CHECK(md5("abc") == "900150983cd24fb0d6963f7d28e17f72");
    CHECK(md5("The quick brown fox jumps over the lazy dog") == "9e107d9d372bb6826bd81d3542a419d6");
    CHECK(md5("12345678901234567890123456789012345678901234567890123456789012345678901234567890") ==
          "57edf4a22be3c955ac49da2e2107b67a");
    CHECK(md5(std::string(55, 'a')) == "ef1772b6dff9a122358552954ad0df65");
    CHECK(md5(std::string(56, 'a')) == "3b0c8ac703f828b04c6c197006d17218");
    CHECK(md5(std::string(64, 'a')) == "014842d480b571495a4a0363793f7367");

    // Signatures: Aho-Corasick finds overlapping and nested patterns, anywhere in the packet
    SignatureEngine sig;
    sig.addPayload("abcd", {'a', 'b', 'c', 'd'});
    sig.addPayload("bc", {'b', 'c'});
    sig.addPayload("MZ-header", {0x4d, 0x5a, 0x90, 0x00});
    sig.finalize();
    CHECK(sig.matchPayload(B("xxbcxx"), 6) && sig.matchPayload(B("xxbcxx"), 6)->name == "bc");
    CHECK(sig.matchPayload(B("xxabcd"), 6).has_value());
    CHECK(!sig.matchPayload(B("xxacbd"), 6).has_value());
    const uint8_t pe[] = {0, 1, 0x4d, 0x5a, 0x90, 0x00, 7};
    CHECK(sig.matchPayload(pe, sizeof pe) && sig.matchPayload(pe, sizeof pe)->name == "MZ-header");
    CHECK(!sig.matchPayload(pe, 5).has_value());  // pattern cut off by the end of the packet
    CHECK(!sig.matchPayload(nullptr, 0).has_value());

    // Rules file parsing, including escapes and error reporting
    {
        const char* path = "/tmp/dpi_sigs_test.txt";
        FILE* f = std::fopen(path, "w");
        std::fputs("# comment\npayload Esc string:A\\x42C\\\\\npayload Hex hex:de ad be ef\ndomain C2 Evil.Example\n"
                   "ip Net 10.1.0.0/16\nip One 192.0.2.7\nja3 Fp e7d705a3286e19ea42f587b344ee6865\n", f);
        std::fclose(f);
        SignatureEngine e;
        std::string err;
        CHECK(e.loadFile(path, &err));
        e.finalize();
        CHECK(e.size() == 6);
        CHECK(e.matchPayload(B("..ABC\\.."), 8).has_value());
        const uint8_t dead[] = {1, 0xde, 0xad, 0xbe, 0xef};
        CHECK(e.matchPayload(dead, sizeof dead).has_value());
        CHECK(e.matchDomain("evil.example")->name == "C2");
        CHECK(e.matchDomain("cdn.EVIL.example").has_value());
        CHECK(!e.matchDomain("notevil.example").has_value());   // must be a real sub-domain
        CHECK(e.matchIp(ipv4(10, 1, 200, 3))->name == "Net");
        CHECK(!e.matchIp(ipv4(10, 2, 0, 1)).has_value());
        CHECK(e.matchIp(ipv4(192, 0, 2, 7))->name == "One");
        CHECK(!e.matchIp(ipv4(192, 0, 2, 8)).has_value());
        CHECK(e.matchJa3("e7d705a3286e19ea42f587b344ee6865")->name == "Fp");

        const char* bad[] = {"payload X string:\\q\n", "payload X hex:abc\n", "ip X 300.1.1.1\n", "ja3 X 123\n",
                             "bogus X y\n", "domain onlyname\n"};
        for (const char* line : bad) {
            f = std::fopen(path, "w");
            std::fputs(line, f);
            std::fclose(f);
            SignatureEngine b;
            std::string e2;
            CHECK(!b.loadFile(path, &e2) && !e2.empty());
        }
        SignatureEngine missing;
        std::string e3;
        CHECK(!missing.loadFile("/nonexistent/file", &e3));
    }

    // Content filter: suffix match on whole labels, custom categories
    ContentFilter cf;
    CHECK(cf.categoryOf("ads.doubleclick.net") == "ads");
    CHECK(cf.categoryOf("DoubleClick.net") == "ads");
    CHECK(cf.categoryOf("notdoubleclick.net").empty());
    CHECK(cf.categoryOf("example.org").empty());
    CHECK(cf.categoryOf("").empty());
    CHECK(cf.hasCategory("Social") && !cf.hasCategory("nope"));
    cf.addDomain("work", "corp.example");
    CHECK(cf.categoryOf("git.corp.example") == "work");

    // P2P detection
    std::string hs = std::string(1, char(19)) + "BitTorrent protocol" + std::string(48, '\0');
    CHECK(isBitTorrent(B(hs), hs.size(), 6));
    CHECK(!isBitTorrent(B(hs), hs.size(), 17));  // handshake only counts on TCP
    CHECK(!isBitTorrent(B(hs), 19, 6));          // truncated
    std::string dht = "d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe";
    CHECK(isBitTorrent(B(dht), dht.size(), 17));
    CHECK(!isBitTorrent(B(dht), dht.size(), 6));
    std::string ann = "GET /announce?info_hash=%12%34&peer_id=x HTTP/1.1\r\nHost: tracker\r\n\r\n";
    CHECK(isBitTorrent(B(ann), ann.size(), 6));
    std::string web = "GET /index.html HTTP/1.1\r\nHost: example.org\r\n\r\n";
    CHECK(!isBitTorrent(B(web), web.size(), 6));

    // Token bucket: 1000 B/s, 1500 B packets (capacity = max(rate, 1500) = 1500)
    TokenBucket tb;
    CHECK(tb.allow(1000, 1500, 1000000));    // starts full
    CHECK(!tb.allow(1000, 1500, 1000000));   // empty, same instant
    CHECK(!tb.allow(1000, 1500, 1500000));   // +500 B, not enough
    CHECK(tb.allow(1000, 1500, 2500000));    // +1000 more = 1500 B
    CHECK(!tb.allow(1000, 1500, 2400000));   // timestamps going backwards must not refill

    std::printf(failures ? "%d test(s) FAILED\n" : "all unit tests passed\n", failures);
    return failures ? 1 : 0;
}
