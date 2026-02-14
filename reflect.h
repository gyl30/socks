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
    bool ok_ = true;

    JsonReader(rapidjson::Value* m) : m(m) {}
    void startObject() {}
    void endObject() {}
    void iterArray(const std::function<void()>& fn);
    void member(const char* name, const std::function<void()>& fn);
    void set_invalid();
    bool ok() const;
    bool isNull();
    std::string getString();
    std::string getPath() const;
};

struct JsonWriter
{
    using W = rapidjson::Writer<rapidjson::StringBuffer, rapidjson::UTF8<char>, rapidjson::UTF8<char>, rapidjson::CrtAllocator, 0>;

    W* m;

    JsonWriter(W* m) : m(m) {}
    void startArray();
    void endArray();
    void startObject();
    void endObject();
    void key(const char* name);
    void null_();
    void int64(std::int64_t v);
    void string(const char* s);
    void string(const char* s, std::size_t len);
};

inline std::string JsonReader::getString() { return m->GetString(); }
inline bool JsonReader::isNull() { return m->IsNull(); }
inline void JsonReader::set_invalid() { ok_ = false; }
inline bool JsonReader::ok() const { return ok_; }
inline std::string JsonReader::getPath() const
{
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
inline void JsonWriter::startArray() { m->StartArray(); }
inline void JsonWriter::endArray() { m->EndArray(); }
inline void JsonWriter::startObject() { m->StartObject(); }
inline void JsonWriter::endObject() { m->EndObject(); }
inline void JsonWriter::key(const char* name) { m->Key(name); }
inline void JsonWriter::null_() { m->Null(); }
inline void JsonWriter::int64(std::int64_t v) { m->Int64(v); }
inline void JsonWriter::string(const char* s) { m->String(s); }
inline void JsonWriter::string(const char* s, std::size_t len) { m->String(s, len); }
inline void reflect(JsonReader& vis, bool& v)
{
    if (!vis.m->IsBool())
    {
        vis.set_invalid();
        return;
    }
    v = vis.m->GetBool();
}
inline void reflect(JsonReader& vis, unsigned char& v)
{
    if (!vis.m->IsInt())
    {
        vis.set_invalid();
        return;
    }
    v = static_cast<std::uint8_t>(vis.m->GetInt());
}
inline void reflect(JsonReader& vis, short& v)
{
    if (!vis.m->IsInt())
    {
        vis.set_invalid();
        return;
    }
    v = static_cast<short>(vis.m->GetInt());
}
inline void reflect(JsonReader& vis, unsigned short& v)
{
    if (!vis.m->IsInt())
    {
        vis.set_invalid();
        return;
    }
    v = static_cast<unsigned short>(vis.m->GetInt());
}
inline void reflect(JsonReader& vis, int8_t& v)
{
    if (!vis.m->IsInt())
    {
        vis.set_invalid();
        return;
    }
    v = static_cast<int8_t>(vis.m->GetInt());
}
inline void reflect(JsonReader& vis, int& v)
{
    if (!vis.m->IsInt())
    {
        vis.set_invalid();
        return;
    }
    v = vis.m->GetInt();
}
inline void reflect(JsonReader& vis, unsigned& v)
{
    if (!vis.m->IsUint64())
    {
        vis.set_invalid();
        return;
    }
    v = static_cast<unsigned>(vis.m->GetUint64());
}
inline void reflect(JsonReader& vis, long& v)
{
    if (!vis.m->IsInt64())
    {
        vis.set_invalid();
        return;
    }
    v = static_cast<long>(vis.m->GetInt64());
}
inline void reflect(JsonReader& vis, unsigned long& v)
{
    if (!vis.m->IsUint64())
    {
        vis.set_invalid();
        return;
    }
    v = static_cast<unsigned long>(vis.m->GetUint64());
}
inline void reflect(JsonReader& vis, long long& v)
{
    if (!vis.m->IsInt64())
    {
        vis.set_invalid();
        return;
    }
    v = vis.m->GetInt64();
}
inline void reflect(JsonReader& vis, unsigned long long& v)
{
    if (!vis.m->IsUint64())
    {
        vis.set_invalid();
        return;
    }
    v = vis.m->GetUint64();
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
inline void reflect(JsonWriter& vis, short& v) { vis.m->Int(v); }
inline void reflect(JsonWriter& vis, unsigned short& v) { vis.m->Int(v); }
inline void reflect(JsonWriter& vis, int& v) { vis.m->Int(v); }
inline void reflect(JsonWriter& vis, int8_t& v) { vis.m->Int(v); }
inline void reflect(JsonWriter& vis, unsigned& v) { vis.m->Uint64(v); }
inline void reflect(JsonWriter& vis, long& v) { vis.m->Int64(v); }
inline void reflect(JsonWriter& vis, unsigned long& v) { vis.m->Uint64(v); }
inline void reflect(JsonWriter& vis, long long& v) { vis.m->Int64(v); }
inline void reflect(JsonWriter& vis, unsigned long long& v) { vis.m->Uint64(v); }
inline void reflect(JsonWriter& vis, double& v) { vis.m->Double(v); }
inline void reflect(JsonWriter& vis, std::string& v) { vis.string(v.c_str(), v.size()); }
inline void reflect(JsonReader& vis, JsonNull& v) {}
inline void reflect(JsonWriter& vis, JsonNull& v) { vis.m->Null(); }

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
inline void reflectMemberStart(T&)
{
}
inline void reflectMemberStart(JsonWriter& vis) { vis.startObject(); }

template <typename T>
inline void reflectMemberEnd(T&)
{
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
    path_.push_back(name);
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

#define _MAPPABLE_REFLECT_MEMBER(name) REFLECT_MEMBER(name);

#define REFLECT_STRUCT(type, ...)                        \
    template <typename Vis>                              \
    void reflect(Vis& vis, type& v)                      \
    {                                                    \
        reflectMemberStart(vis);                         \
        MACRO_MAP(_MAPPABLE_REFLECT_MEMBER, __VA_ARGS__) \
        reflectMemberEnd(vis);                           \
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
    using non_const_t = typename std::remove_const<T>::type;
    auto& nt = const_cast<non_const_t&>(t);
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    JsonWriter json_writer(&writer);
    reflect(json_writer, nt);
    return sb.GetString();
}

}    // namespace reflect

#endif
