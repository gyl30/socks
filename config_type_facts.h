#ifndef CONFIG_TYPE_FACTS_H
#define CONFIG_TYPE_FACTS_H

#include <string_view>

namespace relay
{

namespace config_type
{

constexpr std::string_view kInboundSocks = "socks";
constexpr std::string_view kInboundTproxy = "tproxy";
constexpr std::string_view kInboundTun = "tun";
constexpr std::string_view kInboundReality = "reality";

constexpr std::string_view kOutboundDirect = "direct";
constexpr std::string_view kOutboundBlock = "block";
constexpr std::string_view kOutboundReality = "reality";
constexpr std::string_view kOutboundSocks = "socks";

enum class outbound_class
{
    kUnsupported,
    kDirect,
    kProxy,
    kBlock,
};

[[nodiscard]] constexpr bool is_known_inbound_type(const std::string_view type)
{
    return type == kInboundSocks || type == kInboundTproxy || type == kInboundTun || type == kInboundReality;
}

[[nodiscard]] constexpr bool is_supported_inbound_type(const std::string_view type)
{
    if (type == kInboundSocks || type == kInboundReality)
    {
        return true;
    }
#if SOCKS_HAS_TPROXY
    if (type == kInboundTproxy)
    {
        return true;
    }
#endif
#if SOCKS_HAS_TUN
    if (type == kInboundTun)
    {
        return true;
    }
#endif
    return false;
}

[[nodiscard]] constexpr bool inbound_type_requires_settings(const std::string_view type)
{
    return is_known_inbound_type(type);
}

[[nodiscard]] constexpr bool is_known_outbound_type(const std::string_view type)
{
    return type == kOutboundDirect || type == kOutboundBlock || type == kOutboundReality || type == kOutboundSocks;
}

[[nodiscard]] constexpr bool is_supported_outbound_type(const std::string_view type)
{
    return is_known_outbound_type(type);
}

[[nodiscard]] constexpr bool outbound_type_requires_settings(const std::string_view type)
{
    return type == kOutboundReality || type == kOutboundSocks;
}

[[nodiscard]] constexpr outbound_class classify_outbound_type(const std::string_view type)
{
    if (type == kOutboundDirect)
    {
        return outbound_class::kDirect;
    }
    if (type == kOutboundBlock)
    {
        return outbound_class::kBlock;
    }
    if (type == kOutboundReality || type == kOutboundSocks)
    {
        return outbound_class::kProxy;
    }
    return outbound_class::kUnsupported;
}

}    // namespace config_type

}    // namespace relay

#endif
