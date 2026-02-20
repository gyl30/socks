#include <cctype>
#include <algorithm>
#include <cstddef>
#include <fstream>
#include <string>
#include <string_view>

#include "log.h"
#include "domain_matcher.h"

namespace mux
{

namespace
{

void trim_ascii_whitespace(std::string& line)
{
    line.erase(0, line.find_first_not_of(" \t\r\n"));
    const auto last = line.find_last_not_of(" \t\r\n");
    if (last == std::string::npos)
    {
        line.clear();
        return;
    }
    line.erase(last + 1);
}

std::string sanitize_domain_rule_line(const std::string_view raw_line)
{
    std::string line(raw_line);
    const auto comment_pos = line.find('#');
    if (comment_pos != std::string::npos)
    {
        line.erase(comment_pos);
    }
    trim_ascii_whitespace(line);
    return line;
}

bool read_domain_rule_line(std::ifstream& domain_file, std::string& line)
{
    if (!std::getline(domain_file, line))
    {
        return false;
    }
    line = sanitize_domain_rule_line(line);
    return true;
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
    while (read_domain_rule_line(domain_file, line))
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
