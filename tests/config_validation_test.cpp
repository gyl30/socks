#include <cstdio>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include "config.h"

namespace
{

class temp_file
{
   public:
    temp_file()
    {
        char path_template[] = "/tmp/config_validation_testXXXXXX";
        const int fd = mkstemp(path_template);
        if (fd < 0)
        {
            throw std::runtime_error("failed to create temp file");
        }
        std::fclose(fdopen(fd, "w"));
        path_ = path_template;
    }

    ~temp_file()
    {
        if (!path_.empty())
        {
            std::remove(path_.c_str());
        }
    }

    [[nodiscard]] const std::string& path() const { return path_; }

   private:
    std::string path_;
};

[[noreturn]] void fail(const std::string& message)
{
    throw std::runtime_error(message);
}

void require(const bool condition, const std::string& message)
{
    if (!condition)
    {
        fail(message);
    }
}

std::string make_config_with_timeout_zero(const char* field)
{
    auto json = mux::dump_default_config();
    rapidjson::Document doc;
    doc.Parse(json.c_str());
    if (doc.HasParseError())
    {
        fail("failed to parse default config json");
    }
    auto timeout_it = doc.FindMember("timeout");
    if (timeout_it == doc.MemberEnd() || !timeout_it->value.IsObject())
    {
        fail("default config missing timeout object");
    }
    auto field_it = timeout_it->value.FindMember(field);
    if (field_it == timeout_it->value.MemberEnd() || !field_it->value.IsUint())
    {
        fail(std::string("default config missing timeout field ") + field);
    }
    field_it->value.SetUint(0);

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    doc.Accept(writer);
    return buffer.GetString();
}

std::string make_config_with_replay_cache_zero()
{
    auto json = mux::dump_default_config();
    rapidjson::Document doc;
    doc.Parse(json.c_str());
    if (doc.HasParseError())
    {
        fail("failed to parse default config json");
    }
    auto reality_it = doc.FindMember("reality");
    if (reality_it == doc.MemberEnd() || !reality_it->value.IsObject())
    {
        fail("default config missing reality object");
    }
    auto field_it = reality_it->value.FindMember("replay_cache_max_entries");
    if (field_it == reality_it->value.MemberEnd() || !field_it->value.IsUint())
    {
        fail("default config missing reality replay_cache_max_entries");
    }
    field_it->value.SetUint(0);

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    doc.Accept(writer);
    return buffer.GetString();
}

void run_case(const char* field, const char* expected_path)
{
    temp_file file;
    {
        std::ofstream out(file.path());
        out << make_config_with_timeout_zero(field);
    }

    const auto parsed = mux::parse_config_with_error(file.path());
    require(!parsed.has_value(), std::string("expected parse failure for ") + field);
    require(parsed.error().path == expected_path, std::string("unexpected error path for ") + field + ": " + parsed.error().path);
}

void run_replay_cache_zero_case()
{
    temp_file file;
    {
        std::ofstream out(file.path());
        out << make_config_with_replay_cache_zero();
    }

    const auto parsed = mux::parse_config_with_error(file.path());
    require(!parsed.has_value(), "expected parse failure for replay_cache_max_entries");
    require(parsed.error().path == "/reality/replay_cache_max_entries",
            std::string("unexpected error path for replay_cache_max_entries: ") + parsed.error().path);
}

}    // namespace

int main()
{
    try
    {
        run_case("read", "/timeout/read");
        run_case("write", "/timeout/write");
        run_case("connect", "/timeout/connect");
        run_case("idle", "/timeout/idle");
        run_replay_cache_zero_case();
    }
    catch (const std::exception& e)
    {
        std::cerr << "[FAIL] " << e.what() << '\n';
        return 1;
    }

    std::cout << "[PASS] config validation timeout and replay cache zero rejected\n";
    return 0;
}
