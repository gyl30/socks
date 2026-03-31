#ifndef SECLEAD_BASE_REFLECT_H
#define SECLEAD_BASE_REFLECT_H

#include <map>
#include <memory>
#include <string>
#include <vector>
#include <cassert>
#include <functional>

#include <boost/optional.hpp>
#include <boost/utility/string_view.hpp>
#include <boost/preprocessor/seq/for_each.hpp>

#include "rapidjson/fwd.h"
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
    std::vector<const char*> path_;

    JsonReader(rapidjson::Value* m) : m(m) {}
    void startObject() {}
    void endObject() {}
    void iterArray(const std::function<void()>& fn);
    void member(const char* name, const std::function<void()>& fn);
    bool isNull();
    std::string getString();
    std::string getPath() const;
};
struct JsonPrettyWriter
{
    using W = rapidjson::PrettyWriter<rapidjson::StringBuffer, rapidjson::UTF8<char>, rapidjson::UTF8<char>, rapidjson::CrtAllocator, 0>;

    W* m;

    JsonPrettyWriter(W* m) : m(m) {}
    void startArray();
    void endArray();
    void startObject();
    void endObject();
    void key(const char* name);
    void null_();
    void int64(int64_t v);
    void string(const char* s);
    void string(const char* s, size_t len);
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
    void int64(int64_t v);
    void string(const char* s);
    void string(const char* s, size_t len);
};

// clang-format off

inline     std::string JsonReader::getString() { return m->GetString(); }
inline     bool JsonReader::isNull() { return m->IsNull(); }
inline     void JsonWriter::startArray() { m->StartArray(); }
inline     void JsonWriter::endArray() { m->EndArray(); }
inline     void JsonWriter::startObject() { m->StartObject(); }
inline     void JsonWriter::endObject() { m->EndObject(); }
inline     void JsonWriter::key(const char* name) { m->Key(name); }
inline     void JsonWriter::null_() { m->Null(); }
inline     void JsonWriter::int64(int64_t v) { m->Int64(v); }
inline     void JsonWriter::string(const char* s) { m->String(s); }
inline     void JsonWriter::string(const char* s, size_t len) { m->String(s, static_cast<rapidjson::SizeType>(len)); }
inline     void reflect(JsonReader &vis, bool &v              ) { if (!vis.m->IsBool())   throw std::invalid_argument("bool");               v = vis.m->GetBool(); }
inline     void reflect(JsonReader &vis, unsigned char &v     ) { if (!vis.m->IsInt())    throw std::invalid_argument("uint8_t");            v = (uint8_t)vis.m->GetInt(); }
inline     void reflect(JsonReader &vis, short &v             ) { if (!vis.m->IsInt())    throw std::invalid_argument("short");              v = (short)vis.m->GetInt(); }
inline     void reflect(JsonReader &vis, unsigned short &v    ) { if (!vis.m->IsInt())    throw std::invalid_argument("unsigned short");     v = (unsigned short)vis.m->GetInt(); }
inline     void reflect(JsonReader &vis, int8_t &v            ) { if (!vis.m->IsInt())    throw std::invalid_argument("int8_t");             v = (int8_t)vis.m->GetInt(); }
inline     void reflect(JsonReader &vis, int &v               ) { if (!vis.m->IsInt())    throw std::invalid_argument("int");                v = vis.m->GetInt(); }
inline     void reflect(JsonReader &vis, unsigned &v          ) { if (!vis.m->IsUint64()) throw std::invalid_argument("unsigned");           v = (unsigned)vis.m->GetUint64(); }
inline     void reflect(JsonReader &vis, long &v              ) { if (!vis.m->IsInt64())  throw std::invalid_argument("long");               v = (long)vis.m->GetInt64(); }
inline     void reflect(JsonReader &vis, unsigned long &v     ) { if (!vis.m->IsUint64()) throw std::invalid_argument("unsigned long");      v = (unsigned long)vis.m->GetUint64(); }
inline     void reflect(JsonReader &vis, long long &v         ) { if (!vis.m->IsInt64())  throw std::invalid_argument("long long");          v = vis.m->GetInt64(); }
inline     void reflect(JsonReader &vis, unsigned long long &v) { if (!vis.m->IsUint64()) throw std::invalid_argument("unsigned long long"); v = vis.m->GetUint64(); }
inline     void reflect(JsonReader &vis, double &v            ) { if (!vis.m->IsDouble()) throw std::invalid_argument("double");             v = vis.m->GetDouble(); }
inline     void reflect(JsonReader &vis, std::string &v       ) { if (!vis.m->IsString()) throw std::invalid_argument("string");             v = vis.getString(); }
inline     void reflect(JsonWriter &vis, bool &v              ) { vis.m->Bool(v); }
inline     void reflect(JsonWriter &vis, unsigned char &v     ) { vis.m->Int(v); }
inline     void reflect(JsonWriter &vis, short &v             ) { vis.m->Int(v); }
inline     void reflect(JsonWriter &vis, unsigned short &v    ) { vis.m->Int(v); }
inline     void reflect(JsonWriter &vis, int &v               ) { vis.m->Int(v); }
inline     void reflect(JsonWriter &vis, int8_t &v            ) { vis.m->Int(v); }
inline     void reflect(JsonWriter &vis, unsigned &v          ) { vis.m->Uint64(v); }
inline     void reflect(JsonWriter &vis, long &v              ) { vis.m->Int64(v); }
inline     void reflect(JsonWriter &vis, unsigned long &v     ) { vis.m->Uint64(v); }
inline     void reflect(JsonWriter &vis, long long &v         ) { vis.m->Int64(v); }
inline     void reflect(JsonWriter &vis, unsigned long long &v) { vis.m->Uint64(v); }
inline     void reflect(JsonWriter &vis, double &v            ) { vis.m->Double(v); }
inline     void reflect(JsonWriter &vis, std::string &v       ) { vis.string(v.c_str(), v.size()); }
inline     void reflect(JsonReader& , JsonNull& ) {}
inline     void reflect(JsonWriter& vis, JsonNull& ) { vis.m->Null(); }

//
inline     void JsonPrettyWriter::startArray() { m->StartArray(); }
inline     void JsonPrettyWriter::endArray() { m->EndArray(); }
inline     void JsonPrettyWriter::startObject() { m->StartObject(); }
inline     void JsonPrettyWriter::endObject() { m->EndObject(); }
inline     void JsonPrettyWriter::key(const char* name) { m->Key(name); }
inline     void JsonPrettyWriter::null_() { m->Null(); }
inline     void JsonPrettyWriter::int64(int64_t v) { m->Int64(v); }
inline     void JsonPrettyWriter::string(const char* s) { m->String(s); }
inline     void JsonPrettyWriter::string(const char* s, size_t len) { m->String(s, (rapidjson::SizeType)len); }
inline     void reflect(JsonPrettyWriter &vis, bool &v              ) { vis.m->Bool(v); }
inline     void reflect(JsonPrettyWriter &vis, unsigned char &v     ) { vis.m->Int(v); }
inline     void reflect(JsonPrettyWriter &vis, short &v             ) { vis.m->Int(v); }
inline     void reflect(JsonPrettyWriter &vis, unsigned short &v    ) { vis.m->Int(v); }
inline     void reflect(JsonPrettyWriter &vis, int &v               ) { vis.m->Int(v); }
inline     void reflect(JsonPrettyWriter &vis, int8_t &v            ) { vis.m->Int(v); }
inline     void reflect(JsonPrettyWriter &vis, unsigned &v          ) { vis.m->Uint64(v); }
inline     void reflect(JsonPrettyWriter &vis, long &v              ) { vis.m->Int64(v); }
inline     void reflect(JsonPrettyWriter &vis, unsigned long &v     ) { vis.m->Uint64(v); }
inline     void reflect(JsonPrettyWriter &vis, long long &v         ) { vis.m->Int64(v); }
inline     void reflect(JsonPrettyWriter &vis, unsigned long long &v) { vis.m->Uint64(v); }
inline     void reflect(JsonPrettyWriter &vis, double &v            ) { vis.m->Double(v); }
inline     void reflect(JsonPrettyWriter &vis, std::string &v       ) { vis.string(v.c_str(), v.size()); }
inline     void reflect(JsonPrettyWriter& vis, JsonNull& ) { vis.m->Null(); }

// clang-format on
// boost optional
template <typename T>
void reflect(JsonReader& vis, boost::optional<T>& v)
{
    if (!vis.isNull())
    {
        v.emplace();
        reflect(vis, *v);
    }
}
template <typename T>
void reflect(JsonWriter& vis, boost::string_view& data)
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
void reflect(JsonWriter& vis, boost::optional<T>& v)
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
// std::vector
template <typename T>
inline void reflect(JsonReader& vis, std::vector<T>& v)
{
    vis.iterArray(
        [&]()
        {
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

//
template <typename T>
void reflect(JsonPrettyWriter& vis, boost::string_view& data)
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
void reflect(JsonPrettyWriter& vis, std::map<std::string, T>& v)
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
void reflect(JsonPrettyWriter& vis, boost::optional<T>& v)
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
inline void reflect(JsonPrettyWriter& vis, std::vector<T>& v)
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
        throw std::invalid_argument("object");
    }
}

template <typename T>
inline void reflectMemberStart(T& /*unused*/)
{
}
inline void reflectMemberStart(JsonWriter& vis) { vis.startObject(); }
inline void reflectMemberStart(JsonPrettyWriter& vis) { vis.startObject(); }

template <typename T>
inline void reflectMemberEnd(T& /*unused*/)
{
}
inline void reflectMemberEnd(JsonWriter& vis) { vis.endObject(); }
inline void reflectMemberEnd(JsonPrettyWriter& vis) { vis.endObject(); }

template <typename T>
inline void reflectMember(JsonReader& vis, const char* name, T& v)
{
    vis.member(name, [&]() { reflect(vis, v); });
}
template <typename T>
inline void reflectMember(JsonWriter& vis, const char* name, T& v)
{
    vis.key(name);
    reflect(vis, v);
}
template <typename T>
inline void reflectMember(JsonPrettyWriter& vis, const char* name, T& v)
{
    vis.key(name);
    reflect(vis, v);
}
template <typename T>
inline void reflectMember(JsonWriter& vis, const char* name, boost::optional<T>& v)
{
    if (v.has_value())
    {
        vis.key(name);
        reflect(vis, v);
    }
}
template <typename T>
inline void reflectMember(JsonPrettyWriter& vis, const char* name, boost::optional<T>& v)
{
    if (v.has_value())
    {
        vis.key(name);
        reflect(vis, v);
    }
}

inline void JsonReader::iterArray(const std::function<void()>& fn)
{
    if (!m->IsArray())
    {
        throw std::invalid_argument("array");
    }
    path_.push_back("0");
    for (auto& entry : m->GetArray())
    {
        auto* saved = m;
        m = &entry;
        fn();
        m = saved;
    }
    path_.pop_back();
}
inline void JsonReader::member(const char* name, const std::function<void()>& fn)
{
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

#define _MAPPABLE_REFLECT_MEMBER(unuse, type, name) REFLECT_MEMBER(name);

#define REFLECT_STRUCT(type, ...)                                       \
    template <typename Vis>                                             \
    void reflect(Vis& vis, type& v)                                     \
    {                                                                   \
        reflectMemberStart(vis);                                        \
        BOOST_PP_SEQ_FOR_EACH(_MAPPABLE_REFLECT_MEMBER, _, __VA_ARGS__) \
        reflectMemberEnd(vis);                                          \
    }

template <typename T>
inline bool deserialize_struct(T& t, const std::string& msg)
{
    try
    {
        rapidjson::Document reader;
        const rapidjson::ParseResult ok = reader.Parse(msg.data());
        if (!ok)
        {
            return false;
        }

        JsonReader json_reader{&reader};
        reflect(json_reader, t);
    }
    catch (...)
    {
        return false;
    }
    return true;
}

template <typename T>
inline bool deserialize_struct(T& t, const char* msg, std::size_t lenght)
{
    try
    {
        rapidjson::Document reader;
        const rapidjson::ParseResult ok = reader.Parse(msg, lenght);
        if (!ok)
        {
            return false;
        }
        JsonReader json_reader{&reader};
        reflect(json_reader, t);
    }
    catch (...)
    {
        return false;
    }
    return true;
}
template <typename T>
inline std::string serialize_struct(const T& t)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    JsonWriter json_writer(&writer);
    reflect(json_writer, const_cast<T&>(t));
    return sb.GetString();
}

template <typename T>
inline std::string serialize_struct(T& t)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    JsonWriter json_writer(&writer);
    reflect(json_writer, t);
    return sb.GetString();
}
template <typename T>
inline std::string serialize_struct_pretty(T& t)
{
    rapidjson::StringBuffer sb;
    rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(sb);
    JsonPrettyWriter json_writer(&writer);
    reflect(json_writer, t);
    return sb.GetString();
}
}    // namespace reflect

#endif
