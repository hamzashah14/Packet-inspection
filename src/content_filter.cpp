#include "content_filter.h"

#include <algorithm>
#include <cctype>
#include <fstream>
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

}  // namespace

ContentFilter::ContentFilter() {
    for (const char* d : {"doubleclick.net", "googlesyndication.com", "googleadservices.com", "adservice.google.com",
                          "adnxs.com", "taboola.com", "outbrain.com"})
        addDomain("ads", d);
    for (const char* d : {"facebook.com", "instagram.com", "twitter.com", "x.com", "tiktok.com", "snapchat.com",
                          "reddit.com", "linkedin.com"})
        addDomain("social", d);
    for (const char* d : {"netflix.com", "youtube.com", "twitch.tv", "spotify.com", "hulu.com", "primevideo.com"})
        addDomain("streaming", d);
    for (const char* d : {"steampowered.com", "epicgames.com", "riotgames.com", "roblox.com"})
        addDomain("gaming", d);
    for (const char* d : {"thepiratebay.org", "1337x.to", "nyaa.si", "rarbg.to"}) addDomain("torrents", d);
}

void ContentFilter::addDomain(const std::string& category, const std::string& domain) {
    auto& v = domains_[lower(category)];
    std::string d = lower(domain);
    if (std::find(v.begin(), v.end(), d) == v.end()) v.push_back(d);
}

bool ContentFilter::hasCategory(const std::string& category) const { return domains_.count(lower(category)) > 0; }

std::vector<std::string> ContentFilter::categories() const {
    std::vector<std::string> out;
    for (const auto& [name, _] : domains_) out.push_back(name);
    return out;
}

bool ContentFilter::loadFile(const std::string& path, std::string* err) {
    std::ifstream in(path);
    if (!in) {
        if (err) *err = "cannot open " + path;
        return false;
    }
    std::string line;
    int lineno = 0;
    while (std::getline(in, line)) {
        lineno++;
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        size_t colon = line.find(':');
        if (colon == std::string::npos || colon == 0) {
            if (err) *err = path + ":" + std::to_string(lineno) + ": expected `category: domain, domain`";
            return false;
        }
        std::string category = trim(line.substr(0, colon));
        std::stringstream ss(line.substr(colon + 1));
        std::string item;
        while (std::getline(ss, item, ',')) {
            item = trim(item);
            if (!item.empty()) addDomain(category, item);
        }
    }
    return true;
}

std::string ContentFilter::categoryOf(const std::string& domain) const {
    if (domain.empty()) return "";
    const std::string d = lower(domain);
    for (const auto& [category, patterns] : domains_) {
        for (const auto& p : patterns) {
            if (d == p) return category;
            if (d.size() > p.size() && d.compare(d.size() - p.size(), p.size(), p) == 0 &&
                d[d.size() - p.size() - 1] == '.')
                return category;
        }
    }
    return "";
}

}  // namespace DPI
