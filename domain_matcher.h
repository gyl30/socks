#ifndef DOMAIN_MATCHER_H
#define DOMAIN_MATCHER_H

#include <string>
#include <unordered_set>
#include <algorithm>

namespace mux
{

class domain_matcher
{
   public:
    domain_matcher() = default;

    bool load(const std::string& filename);

    void add(std::string domain);

    bool match(std::string domain) const;

   private:
    std::unordered_set<std::string> domains_;
};

}    // namespace mux

#endif
