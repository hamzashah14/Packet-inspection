#ifndef DPI_CONTENT_FILTER_H
#define DPI_CONTENT_FILTER_H

// Content filtering: group domains into categories (ads, social, ...) and block a whole category.
// A domain pattern matches the name itself or any sub-domain ("doubleclick.net" matches
// "ads.doubleclick.net" but not "notdoubleclick.net").

#include <map>
#include <set>
#include <string>
#include <vector>

namespace DPI {

class ContentFilter {
public:
    ContentFilter();  // starts with a small built-in set of categories

    // Add domains from a file. One category per line: `ads: doubleclick.net, adservice.google.com`.
    // Lines starting with # and blank lines are ignored. Returns false and fills `err` on a bad line.
    bool loadFile(const std::string& path, std::string* err);

    void addDomain(const std::string& category, const std::string& domain);
    bool hasCategory(const std::string& category) const;
    std::vector<std::string> categories() const;

    // Name of the category that `domain` belongs to, or "" when it is in none.
    std::string categoryOf(const std::string& domain) const;

private:
    std::map<std::string, std::vector<std::string>> domains_;  // category -> lower-case domains
};

}  // namespace DPI

#endif  // DPI_CONTENT_FILTER_H
