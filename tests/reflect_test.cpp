#include <map>
#include <vector>
#include <string>
#include <cstdint>
#include <optional>

#include <gtest/gtest.h>

#include "reflect.h"

namespace reflect
{

struct test_struct
{
    bool b;
    std::uint8_t u8;
    int8_t i8;
    short s;
    unsigned short us;
    int i;
    unsigned u;
    long l;
    unsigned long ul;
    long long ll;
    unsigned long long ull;
    double d;
    std::string str;
    std::optional<int> opt_i;
    std::vector<int> vec_i;
};

REFLECT_STRUCT(test_struct, b, u8, i8, s, us, i, u, l, ul, ll, ull, d, str, opt_i, vec_i)

}    // namespace reflect

TEST(ReflectTest, FullRoundTrip)
{
    reflect::test_struct t;
    t.b = true;
    t.u8 = 255;
    t.i8 = 127;
    t.s = -32768;
    t.us = 65535;
    t.i = -123456;
    t.u = 123456;
    t.l = -1234567890L;
    t.ul = 1234567890UL;
    t.ll = -123456789012345LL;
    t.ull = 123456789012345ULL;
    t.d = 3.14159;
    t.str = "hello reflection";
    t.opt_i = 42;
    t.vec_i = {1, 2, 3};

    std::string json = reflect::serialize_struct(t);
    reflect::test_struct t2;
    ASSERT_TRUE(reflect::deserialize_struct(t2, json));

    EXPECT_EQ(t.b, t2.b);
    EXPECT_EQ(t.u8, t2.u8);
    EXPECT_EQ(t.i8, t2.i8);
    EXPECT_EQ(t.s, t2.s);
    EXPECT_EQ(t.us, t2.us);
    EXPECT_EQ(t.i, t2.i);
    EXPECT_EQ(t.u, t2.u);
    EXPECT_EQ(t.l, t2.l);
    EXPECT_EQ(t.ul, t2.ul);
    EXPECT_EQ(t.ll, t2.ll);
    EXPECT_EQ(t.ull, t2.ull);
    EXPECT_DOUBLE_EQ(t.d, t2.d);
    EXPECT_EQ(t.str, t2.str);
    EXPECT_EQ(t.opt_i, t2.opt_i);
    EXPECT_EQ(t.vec_i, t2.vec_i);
}

TEST(ReflectTest, OptionalMissing)
{
    reflect::test_struct t;
    t.opt_i = std::nullopt;
    std::string json = reflect::serialize_struct(t);

    EXPECT_EQ(json.find("opt_i"), std::string::npos);

    reflect::test_struct t2;
    t2.opt_i = 100;
    ASSERT_TRUE(reflect::deserialize_struct(t2, json));
    EXPECT_EQ(t2.opt_i, 100);
}

TEST(ReflectTest, OptionalExplicitNull)
{
    reflect::test_struct t;
    std::string json = R"({"opt_i": null})";
    reflect::test_struct t2;
    t2.opt_i = 100;
    ASSERT_TRUE(reflect::deserialize_struct(t2, json));
    EXPECT_FALSE(t2.opt_i.has_value());
}

TEST(ReflectTest, InvalidJson)
{
    reflect::test_struct t;
    EXPECT_FALSE(reflect::deserialize_struct(t, "{invalid json}"));
}

TEST(ReflectTest, TypeMismatch)
{
    reflect::test_struct t;
    EXPECT_FALSE(reflect::deserialize_struct(t, R"({"b": "not a bool"})"));
    EXPECT_FALSE(reflect::deserialize_struct(t, R"({"u8": "not an int"})"));
    EXPECT_FALSE(reflect::deserialize_struct(t, R"({"s": "not an int"})"));
    EXPECT_FALSE(reflect::deserialize_struct(t, R"({"us": "not an int"})"));
    EXPECT_FALSE(reflect::deserialize_struct(t, R"({"i8": "not an int"})"));
    EXPECT_FALSE(reflect::deserialize_struct(t, R"({"i": "not an int"})"));
    EXPECT_FALSE(reflect::deserialize_struct(t, R"({"u": "not a uint64"})"));
    EXPECT_FALSE(reflect::deserialize_struct(t, R"({"l": "not an int64"})"));
    EXPECT_FALSE(reflect::deserialize_struct(t, R"({"ul": "not a uint64"})"));
    EXPECT_FALSE(reflect::deserialize_struct(t, R"({"ll": "not an int64"})"));
    EXPECT_FALSE(reflect::deserialize_struct(t, R"({"ull": "not a uint64"})"));
    EXPECT_FALSE(reflect::deserialize_struct(t, R"({"d": "not a double"})"));
    EXPECT_FALSE(reflect::deserialize_struct(t, R"({"str": 123})"));
    EXPECT_FALSE(reflect::deserialize_struct(t, R"({"vec_i": "not an array"})"));
    EXPECT_FALSE(reflect::deserialize_struct(t, "[]"));
}

TEST(ReflectTest, JsonNullType)
{
    reflect::JsonNull n;
    std::string json = reflect::serialize_struct(n);
    EXPECT_EQ(json, "null");

    reflect::JsonNull n2;
    rapidjson::Document reader;
    reader.Parse("null");
    reflect::JsonReader jr(&reader);
    reflect::reflect(jr, n2);
}

TEST(ReflectTest, StringViewSerialize)
{
    std::string_view sv = "test view";
    std::string json = reflect::serialize_struct(sv);
    EXPECT_EQ(json, R"("test view")");

    std::string_view empty_sv;
    json = reflect::serialize_struct(empty_sv);
    EXPECT_EQ(json, R"("")");
}

TEST(ReflectTest, CharPointerDeserialize)
{
    reflect::test_struct t;
    std::string json = R"({"i": 123})";
    ASSERT_TRUE(reflect::deserialize_struct(t, json.c_str(), json.size()));
    EXPECT_EQ(t.i, 123);
}
