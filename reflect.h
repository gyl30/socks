#ifndef REFLECT_H
#define REFLECT_H

#include <map>
#include <memory>
#include <string>
#include <vector>
#include <cassert>
#include <cstdint>
#include <optional>
#include <functional>
#include <limits>
#include <string_view>
#include <type_traits>

#include "rapidjson/fwd.h"
#include "third/macro_map.h"
#include "rapidjson/document.h"
#include "rapidjson/prettywriter.h"

namespace reflect
{
struct JsonNull
{
};

struct JsonReader
{
    rapidjson::Value* m;
    std::vector<std::string> path_;
    std::string invalid_path_;
    bool ok_ = true;

    explicit JsonReader(rapidjson::Value* m) : m(m) {}
    void startObject() {}
    void endObject() {}
    void iterArray(const std::function<void()>& fn);
    void member(const char* name, const std::function<void()>& fn);
    void set_invalid();
    [[nodiscard]] bool ok() const;
    [[nodiscard]] bool isNull() const;
    [[nodiscard]] std::string getString() const;
    [[nodiscard]] std::string getPath() const;
};

struct JsonWriter
{
    using W = rapidjson::Writer<rapidjson::StringBuffer, rapidjson::UTF8<char>, rapidjson::UTF8<char>, rapidjson::CrtAllocator, 0>;

    W* m;

    explicit JsonWriter(W* m) : m(m) {}
    void startArray() const;
    void endArray() const;
    void startObject() const;
    void endObject() const;
    void key(const char* name) const;
    void null_() const;
    void int64(std::int64_t v) const;
    void string(const char* s) const;
    void string(const char* s, std::size_t len) const;
};

inline std::string JsonReader::getString() const { return m->GetString(); }
inline bool JsonReader::isNull() const { return m->IsNull(); }
inline void JsonReader::set_invalid()
{
    if (!ok_)
    {
        return;
    }
    invalid_path_ = getPath();
    ok_ = false;
}
inline bool JsonReader::ok() const { return ok_; }
inline std::string JsonReader::getPath() const
{
    if (!ok_)
    {
        if (!invalid_path_.empty())
        {
            return invalid_path_;
        }
        return "/";
    }

    if (path_.empty())
    {
        return "/";
    }

    std::string result = "/";
    for (std::size_t i = 0; i < path_.size(); ++i)
    {
        if (i != 0)
        {
            result.push_back('/');
        }
        result.append(path_[i]);
    }
    return result;
}
inline void JsonWriter::startArray() const { m->StartArray(); }
inline void JsonWriter::endArray() const { m->EndArray(); }
inline void JsonWriter::startObject() const { m->StartObject(); }
inline void JsonWriter::endObject() const { m->EndObject(); }
inline void JsonWriter::key(const char* name) const { m->Key(name); }
inline void JsonWriter::null_() const { m->Null(); }
inline void JsonWriter::int64(std::int64_t v) const { m->Int64(v); }
inline void JsonWriter::string(const char* s) const { m->String(s); }
inline void JsonWriter::string(const char* s, std::size_t len) const
{
    assert(len <= static_cast<std::size_t>(std::numeric_limits<rapidjson::SizeType>::max()));
    m->String(s, static_cast<rapidjson::SizeType>(len));
}

template <typename T>
bool read_signed_integer(JsonReader& vis, T& out)
{
    if (!vis.m->IsInt64())
    {
        vis.set_invalid();
        return false;
    }
    const auto value = vis.m->GetInt64();
    if (value < static_cast<std::int64_t>(std::numeric_limits<T>::min()) || value > static_cast<std::int64_t>(std::numeric_limits<T>::max()))
    {
        vis.set_invalid();
        return false;
    }
    out = static_cast<T>(value);
    return true;
}

template <typename T>
bool read_unsigned_integer(JsonReader& vis, T& out)
{
    if (!vis.m->IsUint64())
    {
        vis.set_invalid();
        return false;
    }
    const auto value = vis.m->GetUint64();
    if (value > static_cast<std::uint64_t>(std::numeric_limits<T>::max()))
    {
        vis.set_invalid();
        return false;
    }
    out = static_cast<T>(value);
    return true;
}

inline void reflect(JsonReader& vis, bool& v)
{
    if (!vis.m->IsBool())
    {
        vis.set_invalid();
        return;
    }
    v = vis.m->GetBool();
}
inline void reflect(JsonReader& vis, unsigned char& v) { (void)read_unsigned_integer(vis, v); }
template <typename T, std::enable_if_t<std::is_integral_v<T> && std::is_signed_v<T> && !std::is_same_v<T, bool> && !std::is_same_v<T, char>, int> = 0>
inline void reflect(JsonReader& vis, T& v)
{
    (void)read_signed_integer(vis, v);
}
template <typename T,
          std::enable_if_t<std::is_integral_v<T> && std::is_unsigned_v<T> && !std::is_same_v<T, bool> && !std::is_same_v<T, char> &&
                               !std::is_same_v<T, unsigned char>,
                           int> = 0>
inline void reflect(JsonReader& vis, T& v)
{
    (void)read_unsigned_integer(vis, v);
}
inline void reflect(JsonReader& vis, double& v)
{
    if (!vis.m->IsDouble())
    {
        vis.set_invalid();
        return;
    }
    v = vis.m->GetDouble();
}
inline void reflect(JsonReader& vis, std::string& v)
{
    if (!vis.m->IsString())
    {
        vis.set_invalid();
        return;
    }
    v = vis.getString();
}
inline void reflect(JsonWriter& vis, bool& v) { vis.m->Bool(v); }
inline void reflect(JsonWriter& vis, unsigned char& v) { vis.m->Int(v); }
template <typename T, std::enable_if_t<std::is_integral_v<T> && std::is_signed_v<T> && !std::is_same_v<T, bool> && !std::is_same_v<T, char>, int> = 0>
inline void reflect(JsonWriter& vis, T& v)
{
    vis.m->Int64(static_cast<std::int64_t>(v));
}
template <typename T,
          std::enable_if_t<std::is_integral_v<T> && std::is_unsigned_v<T> && !std::is_same_v<T, bool> && !std::is_same_v<T, char> &&
                               !std::is_same_v<T, unsigned char>,
                           int> = 0>
inline void reflect(JsonWriter& vis, T& v)
{
    vis.m->Uint64(static_cast<std::uint64_t>(v));
}
inline void reflect(JsonWriter& vis, double& v) { vis.m->Double(v); }
inline void reflect(JsonWriter& vis, std::string& v) { vis.string(v.c_str(), v.size()); }
inline void reflect(JsonReader& vis, JsonNull& value)
{
    (void)vis;
    (void)value;
}
inline void reflect(JsonWriter& vis, [[maybe_unused]] JsonNull& value) { vis.m->Null(); }

template <typename T>
void reflect(JsonReader& vis, std::optional<T>& v)
{
    if (!vis.ok())
    {
        return;
    }
    if (vis.isNull())
    {
        v = std::nullopt;
    }
    else
    {
        v.emplace();
        reflect(vis, *v);
    }
}
inline void reflect(JsonWriter& vis, std::string_view& data)
{
    if (data.empty())
    {
        vis.string("");
    }
    else
    {
        vis.string(data.data(), static_cast<rapidjson::SizeType>(data.size()));
    }
}
template <typename T>
void reflect(JsonWriter& vis, std::map<std::string, T>& v)
{
    vis.startObject();
    for (auto& pair : v)
    {
        vis.key(pair.first.data());
        reflect(vis, pair.second);
    }
    vis.endObject();
}
template <typename T>
void reflect(JsonWriter& vis, std::optional<T>& v)
{
    if (v)
    {
        reflect(vis, *v);
    }
    else
    {
        vis.null_();
    }
}

template <typename T>
inline void reflect(JsonReader& vis, std::vector<T>& v)
{
    if (!vis.ok())
    {
        return;
    }
    vis.iterArray(
        [&]()
        {
            if (!vis.ok())
            {
                return;
            }
            v.emplace_back();
            reflect(vis, v.back());
        });
}
template <typename T>
inline void reflect(JsonWriter& vis, std::vector<T>& v)
{
    vis.startArray();
    for (auto& it : v)
    {
        reflect(vis, it);
    }
    vis.endArray();
}

inline void reflectMemberStart(JsonReader& vis)
{
    if (!vis.m->IsObject())
    {
        vis.set_invalid();
    }
}

template <typename T>
inline void reflectMemberStart(T& unused)
{
    (void)unused;
}
inline void reflectMemberStart(JsonWriter& vis) { vis.startObject(); }

template <typename T>
inline void reflectMemberEnd(T& unused)
{
    (void)unused;
}
inline void reflectMemberEnd(JsonWriter& vis) { vis.endObject(); }

template <typename T>
inline void reflectMember(JsonReader& vis, const char* name, T& v)
{
    if (!vis.ok())
    {
        return;
    }
    vis.member(name, [&]() { reflect(vis, v); });
}
template <typename T>
inline void reflectMember(JsonWriter& vis, const char* name, T& v)
{
    vis.key(name);
    reflect(vis, v);
}

template <typename T>
inline void reflectMember(JsonWriter& vis, const char* name, std::optional<T>& v)
{
    if (v.has_value())
    {
        vis.key(name);
        reflect(vis, v);
    }
}

inline void JsonReader::iterArray(const std::function<void()>& fn)
{
    if (!ok_)
    {
        return;
    }
    if (!m->IsArray())
    {
        set_invalid();
        return;
    }
    path_.emplace_back("0");
    std::size_t index = 0;
    for (auto& entry : m->GetArray())
    {
        if (!ok_)
        {
            break;
        }
        path_.back() = std::to_string(index);
        auto* saved = m;
        m = &entry;
        fn();
        m = saved;
        ++index;
    }
    path_.pop_back();
}
inline void JsonReader::member(const char* name, const std::function<void()>& fn)
{
    if (!ok_)
    {
        return;
    }
    path_.emplace_back(name);
    auto it = m->FindMember(name);
    if (it != m->MemberEnd())
    {
        auto* saved = m;
        m = &it->value;
        fn();
        m = saved;
    }
    path_.pop_back();
}

#define REFLECT_MEMBER(name) reflectMember(vis, #name, v.name)

#define MAPPABLE_REFLECT_MEMBER(name) REFLECT_MEMBER(name);

#define REFLECT_STRUCT(type, ...)                       \
    template <typename Vis>                             \
    void reflect(Vis& vis, type& v)                     \
    {                                                   \
        reflectMemberStart(vis);                        \
        MACRO_MAP(MAPPABLE_REFLECT_MEMBER, __VA_ARGS__) \
        reflectMemberEnd(vis);                          \
    }

template <typename T>
inline bool deserialize_struct(T& t, const std::string& msg)
{
    rapidjson::Document reader;
    const rapidjson::ParseResult ok = reader.Parse(msg.data());
    if (!ok)
    {
        return false;
    }

    JsonReader json_reader{&reader};
    reflect(json_reader, t);
    return json_reader.ok();
}

template <typename T>
inline bool deserialize_struct(T& t, const char* msg, std::size_t lenght)
{
    rapidjson::Document reader;
    const rapidjson::ParseResult ok = reader.Parse(msg, lenght);
    if (!ok)
    {
        return false;
    }

    JsonReader json_reader{&reader};
    reflect(json_reader, t);
    return json_reader.ok();
}

template <typename T>
inline std::string serialize_struct(const T& t)
{
    using non_const_t = std::remove_const_t<T>;
    auto& nt = const_cast<non_const_t&>(t);
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    JsonWriter json_writer(&writer);
    reflect(json_writer, nt);
    return sb.GetString();
}

}    // namespace reflect

#endif
