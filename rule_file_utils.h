#ifndef RULE_FILE_UTILS_H
#define RULE_FILE_UTILS_H

#include <string>
#include <fstream>
#include <string_view>

namespace relay::rule_file_util
{

inline void trim_ascii_whitespace(std::string& line)
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

[[nodiscard]] inline std::string sanitize_rule_line(const std::string_view raw_line)
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

inline bool read_rule_line(std::ifstream& file, std::string& line)
{
    if (!std::getline(file, line))
    {
        return false;
    }
    line = sanitize_rule_line(line);
    return true;
}

}    // namespace relay::rule_file_util

#endif
