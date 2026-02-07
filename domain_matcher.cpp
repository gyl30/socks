#include <string>
#include <cctype>
#include <fstream>
#include <cstddef>
#include <algorithm>

#include "log.h"
#include "domain_matcher.h"

namespace mux
{

bool domain_matcher::load(const std::string& filename)
{
    std::ifstream file(filename);
    if (!file.is_open())
    {
        LOG_WARN("failed to open domain file {}", filename);
        return false;
    }

    std::string line;
    while (std::getline(file, line))
    {
        const auto comment_pos = line.find('#');
        if (comment_pos != std::string::npos)
        {
            line = line.substr(0, comment_pos);
        }

        line.erase(0, line.find_first_not_of(" \t\r\n"));
        const auto last = line.find_last_not_of(" \t\r\n");
        if (last != std::string::npos)
        {
            line.erase(last + 1);
        }
        else
        {
            line.clear();
        }

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
    if (domain.back() == '.')
    {
        domain.pop_back();
    }
    std::ranges::transform(domain, domain.begin(), [](const unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    (void)domains_.insert(domain);
}

bool domain_matcher::match(std::string domain) const
{
    if (domain.empty())
    {
        return false;
    }

    if (domain.back() == '.')
    {
        domain.pop_back();
    }

    std::ranges::transform(domain, domain.begin(), [](const unsigned char ch) { return static_cast<char>(std::tolower(ch)); });

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
