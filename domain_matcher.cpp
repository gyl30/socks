#include <cctype>
#include <string>
#include <cstddef>
#include <fstream>
#include <algorithm>

#include "log.h"
#include "domain_matcher.h"
#include "rule_file_utils.h"

namespace mux
{

namespace
{

void normalize_domain(std::string& domain)
{
    if (!domain.empty() && domain.back() == '.')
    {
        domain.pop_back();
    }
    std::ranges::transform(domain, domain.begin(), [](const unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
}

}    // namespace

bool domain_matcher::load(const std::string& filename)
{
    std::ifstream domain_file(filename);
    if (!domain_file.is_open())
    {
        LOG_WARN("failed to open domain file {}", filename);
        return false;
    }

    std::string line;
    while (rule_file_util::read_rule_line(domain_file, line))
    {
        if (line.empty())
        {
            continue;
        }

        add(line);
    }
    LOG_INFO("loaded {} proxy domain rules", domains_.size());
    return true;
}

void domain_matcher::add(std::string domain)
{
    if (domain.empty())
    {
        return;
    }
    normalize_domain(domain);
    (void)domains_.insert(domain);
}

bool domain_matcher::match(std::string domain) const
{
    if (domain.empty())
    {
        return false;
    }
    normalize_domain(domain);

    if (domains_.contains(domain))
    {
        return true;
    }

    std::size_t pos = 0;
    while ((pos = domain.find('.', pos)) != std::string::npos)
    {
        const std::string suffix = domain.substr(pos + 1);
        if (domains_.contains(suffix))
        {
            return true;
        }
        pos++;
    }

    return false;
}

}    // namespace mux
