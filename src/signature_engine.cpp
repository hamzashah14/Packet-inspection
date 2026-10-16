#include "signature_engine.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <queue>
#include <sstream>

namespace DPI {

namespace {

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

int hexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// "abc\x41\\" -> bytes; false on a bad escape
bool unescape(const std::string& in, std::vector<uint8_t>* out) {
    for (size_t i = 0; i < in.size(); i++) {
        if (in[i] != '\\') {
            out->push_back(static_cast<uint8_t>(in[i]));
        } else if (i + 1 < in.size() && in[i + 1] == '\\') {
            out->push_back('\\');
            i++;
        } else if (i + 3 < in.size() && in[i + 1] == 'x' && hexVal(in[i + 2]) >= 0 && hexVal(in[i + 3]) >= 0) {
            out->push_back(static_cast<uint8_t>(hexVal(in[i + 2]) * 16 + hexVal(in[i + 3])));
            i += 3;
        } else {
            return false;
        }
    }
    return true;
}

bool parseDottedQuad(const std::string& s, uint32_t* out) {
    unsigned parts[4];
    char dot;
    std::istringstream is(s);
    for (int i = 0; i < 4; i++) {
        if (!(is >> parts[i]) || parts[i] > 255) return false;
        if (i < 3 && (!(is >> dot) || dot != '.')) return false;
    }
    *out = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
    return is.peek() == EOF;
}

}  // namespace

bool SignatureEngine::addPayload(const std::string& name, const std::vector<uint8_t>& bytes) {
    if (bytes.empty()) return false;
    payloads_.push_back(bytes);
    payload_names_.push_back(name);
    return true;
}

void SignatureEngine::addDomain(const std::string& name, const std::string& domain) {
    domains_.emplace_back(name, lower(domain));
}

bool SignatureEngine::addIp(const std::string& name, const std::string& ip_or_cidr) {
    std::string addr = ip_or_cidr;
    int prefix = 32;
    size_t slash = ip_or_cidr.find('/');
    if (slash != std::string::npos) {
        addr = ip_or_cidr.substr(0, slash);
        try {
            prefix = std::stoi(ip_or_cidr.substr(slash + 1));
        } catch (...) {
            return false;
        }
        if (prefix < 0 || prefix > 32) return false;
    }
    uint32_t ip;
    if (!parseDottedQuad(addr, &ip)) return false;
    uint32_t mask = prefix == 0 ? 0 : (0xFFFFFFFFu << (32 - prefix));
    ips_.push_back({name, ip & mask, mask});
    return true;
}

bool SignatureEngine::addJa3(const std::string& name, const std::string& md5) {
    if (md5.size() != 32 || !std::all_of(md5.begin(), md5.end(), [](unsigned char c) { return std::isxdigit(c); }))
        return false;
    ja3_.emplace_back(name, lower(md5));
    return true;
}

bool SignatureEngine::loadFile(const std::string& path, std::string* err) {
    std::ifstream in(path);
    if (!in) {
        if (err) *err = "cannot open " + path;
        return false;
    }
    std::string line;
    int lineno = 0;
    auto fail = [&](const std::string& why) {
        if (err) *err = path + ":" + std::to_string(lineno) + ": " + why;
        return false;
    };
    while (std::getline(in, line)) {
        lineno++;
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        std::istringstream is(line);
        std::string type, name;
        is >> type >> name;
        std::string rest;
        std::getline(is, rest);
        rest = trim(rest);
        if (name.empty() || rest.empty()) return fail("expected `<type> <name> <pattern>`");

        if (type == "payload") {
            std::vector<uint8_t> bytes;
            if (rest.rfind("string:", 0) == 0) {
                if (!unescape(rest.substr(7), &bytes)) return fail("bad escape in string pattern");
            } else if (rest.rfind("hex:", 0) == 0) {
                std::string h = rest.substr(4);
                h.erase(std::remove_if(h.begin(), h.end(), [](unsigned char c) { return std::isspace(c); }), h.end());
                if (h.empty() || h.size() % 2) return fail("hex pattern needs an even number of digits");
                for (size_t i = 0; i < h.size(); i += 2) {
                    int hi = hexVal(h[i]), lo = hexVal(h[i + 1]);
                    if (hi < 0 || lo < 0) return fail("bad hex digit");
                    bytes.push_back(static_cast<uint8_t>(hi * 16 + lo));
                }
            } else {
                return fail("payload pattern must start with string: or hex:");
            }
            if (!addPayload(name, bytes)) return fail("empty payload pattern");
        } else if (type == "domain") {
            addDomain(name, rest);
        } else if (type == "ip") {
            if (!addIp(name, rest)) return fail("bad IP or CIDR: " + rest);
        } else if (type == "ja3") {
            if (!addJa3(name, rest)) return fail("JA3 must be 32 hex digits");
        } else {
            return fail("unknown signature type `" + type + "`");
        }
    }
    return true;
}

void SignatureEngine::finalize() {
    nodes_.clear();
    nodes_.emplace_back();  // root
    for (size_t id = 0; id < payloads_.size(); id++) {
        int cur = 0;
        for (uint8_t b : payloads_[id]) {
            if (nodes_[cur].next[b] < 0) {
                nodes_[cur].next[b] = static_cast<int32_t>(nodes_.size());
                nodes_.emplace_back();
            }
            cur = nodes_[cur].next[b];
        }
        nodes_[cur].out.push_back(static_cast<int>(id));
    }
    // Breadth-first: failure links, then turn the trie into a full DFA so scanning is one lookup per byte.
    std::vector<int> fail(nodes_.size(), 0);
    std::queue<int> q;
    for (int c = 0; c < 256; c++) {
        int child = nodes_[0].next[c];
        if (child < 0) nodes_[0].next[c] = 0;
        else q.push(child);
    }
    while (!q.empty()) {
        int u = q.front();
        q.pop();
        for (int id : nodes_[fail[u]].out) nodes_[u].out.push_back(id);
        for (int c = 0; c < 256; c++) {
            int v = nodes_[u].next[c];
            if (v < 0) {
                nodes_[u].next[c] = nodes_[fail[u]].next[c];
            } else {
                fail[v] = nodes_[fail[u]].next[c];
                q.push(v);
            }
        }
    }
}

std::optional<SignatureMatch> SignatureEngine::matchPayload(const uint8_t* data, size_t len) const {
    if (nodes_.empty()) return std::nullopt;
    int cur = 0;
    for (size_t i = 0; i < len; i++) {
        cur = nodes_[cur].next[data[i]];
        if (!nodes_[cur].out.empty()) return SignatureMatch{payload_names_[nodes_[cur].out.front()], "payload"};
    }
    return std::nullopt;
}

std::optional<SignatureMatch> SignatureEngine::matchDomain(const std::string& domain) const {
    if (domain.empty()) return std::nullopt;
    const std::string d = lower(domain);
    for (const auto& [name, p] : domains_) {
        if (d == p) return SignatureMatch{name, "domain"};
        if (d.size() > p.size() && d.compare(d.size() - p.size(), p.size(), p) == 0 && d[d.size() - p.size() - 1] == '.')
            return SignatureMatch{name, "domain"};
    }
    return std::nullopt;
}

std::optional<SignatureMatch> SignatureEngine::matchIp(uint32_t ip) const {
    // engine order (first octet lowest) -> a<<24|b<<16|c<<8|d
    uint32_t host = ((ip & 0xFF) << 24) | (((ip >> 8) & 0xFF) << 16) | (((ip >> 16) & 0xFF) << 8) | ((ip >> 24) & 0xFF);
    for (const auto& c : ips_)
        if ((host & c.mask) == c.network) return SignatureMatch{c.name, "ip"};
    return std::nullopt;
}

std::optional<SignatureMatch> SignatureEngine::matchJa3(const std::string& md5) const {
    for (const auto& [name, h] : ja3_)
        if (h == md5) return SignatureMatch{name, "ja3"};
    return std::nullopt;
}

}  // namespace DPI
