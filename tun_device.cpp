#include <cerrno>
#include <cstdio>
#include <string>
#include <cstring>
#include <utility>
#include <algorithm>
#include <type_traits>
#ifdef _WIN32
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <fcntl.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#if defined(__linux__)
#include <arpa/inet.h>
#include <linux/ipv6.h>
#include <netinet/in.h>
#include <linux/if_tun.h>
#endif

#if defined(__APPLE__) || defined(__MACH__)
#include <sys/uio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if_utun.h>
#include <netinet6/nd6.h>
#include <netinet/in_var.h>
#include <sys/sys_domain.h>
#include <sys/kern_control.h>
#include <TargetConditionals.h>
#endif
#endif

#include <boost/system/errc.hpp>
#ifdef _WIN32
#include "wintun.h"
#pragma comment(lib, "iphlpapi.lib")
#endif

#include "tun_device.h"
namespace mux
{

namespace
{

boost::system::error_code errno_ec() { return {errno, boost::system::system_category()}; }

#ifdef _WIN32
boost::system::error_code win32_ec()
{
    return {static_cast<int>(GetLastError()), boost::system::system_category()};
}

boost::system::error_code win32_result_ec(const DWORD result)
{
    return {static_cast<int>(result), boost::system::system_category()};
}

std::wstring utf8_to_wstring(const std::string& text)
{
    if (text.empty())
    {
        return {};
    }

    const int length = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, nullptr, 0);
    if (length <= 0)
    {
        return {};
    }

    std::wstring out(static_cast<std::size_t>(length), L'\0');
    const int converted = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, out.data(), length);
    if (converted <= 0)
    {
        return {};
    }
    out.resize(static_cast<std::size_t>(converted - 1));
    return out;
}
#endif

#ifndef _WIN32
uint32_t prefix_mask_v4(uint8_t prefix)
{
    if (prefix == 0)
    {
        return 0;
    }
    if (prefix >= 32)
    {
        return 0xFFFFFFFFU;
    }
    return 0xFFFFFFFFU << (32U - prefix);
}
#endif

}    // namespace

#ifdef _WIN32
struct tun_device::windows_state
{
    HMODULE module = nullptr;
    WINTUN_ADAPTER_HANDLE adapter = nullptr;
    WINTUN_SESSION_HANDLE session = nullptr;
    WINTUN_CREATE_ADAPTER_FUNC* create_adapter = nullptr;
    WINTUN_CLOSE_ADAPTER_FUNC* close_adapter = nullptr;
    WINTUN_GET_ADAPTER_LUID_FUNC* get_adapter_luid = nullptr;
    WINTUN_START_SESSION_FUNC* start_session = nullptr;
    WINTUN_END_SESSION_FUNC* end_session = nullptr;
    WINTUN_GET_READ_WAIT_EVENT_FUNC* get_read_wait_event = nullptr;
    WINTUN_RECEIVE_PACKET_FUNC* receive_packet = nullptr;
    WINTUN_RELEASE_RECEIVE_PACKET_FUNC* release_receive_packet = nullptr;
    WINTUN_ALLOCATE_SEND_PACKET_FUNC* allocate_send_packet = nullptr;
    WINTUN_SEND_PACKET_FUNC* send_packet = nullptr;
};
#endif

tun_device::~tun_device() { close(); }

bool tun_device::open(const config::tun_t& cfg, boost::system::error_code& ec)
{
    ec.clear();
    close();

#ifdef _WIN32
    auto state = std::make_unique<windows_state>();
    state->module = LoadLibraryExW(L"wintun.dll", nullptr, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (state->module == nullptr)
    {
        ec = win32_ec();
        return false;
    }

    auto load_proc = [&](auto& fn, const char* name) -> bool
    {
        fn = reinterpret_cast<std::remove_reference_t<decltype(fn)>>(GetProcAddress(state->module, name));
        if (fn == nullptr)
        {
            ec = win32_ec();
            return false;
        }
        return true;
    };

    if (!load_proc(state->create_adapter, "WintunCreateAdapter") || !load_proc(state->close_adapter, "WintunCloseAdapter") ||
        !load_proc(state->get_adapter_luid, "WintunGetAdapterLUID") || !load_proc(state->start_session, "WintunStartSession") ||
        !load_proc(state->end_session, "WintunEndSession") || !load_proc(state->get_read_wait_event, "WintunGetReadWaitEvent") ||
        !load_proc(state->receive_packet, "WintunReceivePacket") || !load_proc(state->release_receive_packet, "WintunReleaseReceivePacket") ||
        !load_proc(state->allocate_send_packet, "WintunAllocateSendPacket") || !load_proc(state->send_packet, "WintunSendPacket"))
    {
        close();
        return false;
    }

    const std::string requested_name = cfg.name.empty() ? std::string("socks-tun") : cfg.name;
    const auto adapter_name = utf8_to_wstring(requested_name);
    if (adapter_name.empty())
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        close();
        return false;
    }

    state->adapter = state->create_adapter(adapter_name.c_str(), L"Socks", nullptr);
    if (state->adapter == nullptr)
    {
        ec = win32_ec();
        close();
        return false;
    }

    state->session = state->start_session(state->adapter, 0x400000);
    if (state->session == nullptr)
    {
        ec = win32_ec();
        close();
        return false;
    }

    NET_LUID luid{};
    state->get_adapter_luid(state->adapter, &luid);
    NET_IFINDEX index = 0;
    const DWORD index_result = ConvertInterfaceLuidToIndex(&luid, &index);
    if (index_result != NO_ERROR)
    {
        ec = win32_result_ec(index_result);
        close();
        return false;
    }

    name_ = requested_name;
    index_ = std::to_string(index);
    windows_ = state.release();
#elif defined(__linux__)
    const int fd = ::open("/dev/net/tun", O_RDWR | O_NONBLOCK);
    if (fd < 0)
    {
        ec = errno_ec();
        return false;
    }

    ifreq ifr{};
    ifr.ifr_flags = static_cast<short>(IFF_TUN | IFF_NO_PI);
    if (!cfg.name.empty())
    {
        std::strncpy(ifr.ifr_name, cfg.name.c_str(), IFNAMSIZ - 1);
    }

    if (::ioctl(fd, TUNSETIFF, &ifr) != 0)
    {
        ec = errno_ec();
        ::close(fd);
        return false;
    }

    fd_ = fd;
    name_ = ifr.ifr_name;
    index_ = std::to_string(if_nametoindex(ifr.ifr_name));
#elif defined(__APPLE__) || defined(__MACH__)
#if TARGET_OS_OSX
    ctl_info info{};
    std::strncpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name) - 1);

    const int fd = ::socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0)
    {
        ec = errno_ec();
        return false;
    }

    if (::ioctl(fd, CTLIOCGINFO, &info) != 0)
    {
        ec = errno_ec();
        ::close(fd);
        return false;
    }

    sockaddr_ctl addr{};
    addr.sc_id = info.ctl_id;
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_unit = 0;

    if (!cfg.name.empty())
    {
        unsigned int requested_unit = 0;
        if (std::sscanf(cfg.name.c_str(), "utun%u", &requested_unit) == 1)
        {
            addr.sc_unit = requested_unit + 1U;
        }
    }

    if (::connect(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0)
    {
        ec = errno_ec();
        ::close(fd);
        return false;
    }

    int nonblock = 1;
    if (::ioctl(fd, FIONBIO, reinterpret_cast<char*>(&nonblock)) != 0)
    {
        ec = errno_ec();
        ::close(fd);
        return false;
    }

    char if_name[IFNAMSIZ] = {0};
    socklen_t if_name_len = sizeof(if_name);
    if (::getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, if_name, &if_name_len) != 0)
    {
        ec = errno_ec();
        ::close(fd);
        return false;
    }

    fd_ = fd;
    name_ = if_name;
    index_ = std::to_string(if_nametoindex(if_name));
#else
    ec = boost::system::errc::make_error_code(boost::system::errc::not_supported);
    return false;
#endif
#else
    ec = boost::system::errc::make_error_code(boost::system::errc::not_supported);
    return false;
#endif

    if (!configure(cfg, ec))
    {
        close();
        return false;
    }

    return true;
}

bool tun_device::configure(const config::tun_t& cfg, boost::system::error_code& ec)
{
    ec.clear();

#ifdef _WIN32
    if (windows_ == nullptr)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_file_descriptor);
        return false;
    }

    NET_LUID luid{};
    windows_->get_adapter_luid(windows_->adapter, &luid);

    MIB_IFROW if_row{};
    const DWORD index_result = ConvertInterfaceLuidToIndex(&luid, &if_row.dwIndex);
    if (index_result != NO_ERROR)
    {
        ec = win32_result_ec(index_result);
        return false;
    }

    const DWORD get_if_result = GetIfEntry(&if_row);
    if (get_if_result != NO_ERROR)
    {
        ec = win32_result_ec(get_if_result);
        return false;
    }
    if_row.dwMtu = cfg.mtu;
    const DWORD set_if_result = SetIfEntry(&if_row);
    if (set_if_result != NO_ERROR)
    {
        ec = win32_result_ec(set_if_result);
        return false;
    }

    auto set_unicast_address = [&](int family, const void* raw_addr, uint8_t prefix) -> bool
    {
        MIB_UNICASTIPADDRESS_ROW address_row;
        InitializeUnicastIpAddressEntry(&address_row);
        address_row.InterfaceLuid = luid;
        address_row.OnLinkPrefixLength = prefix;
        address_row.DadState = IpDadStatePreferred;
        if (family == AF_INET)
        {
            address_row.Address.Ipv4.sin_family = AF_INET;
            std::memcpy(&address_row.Address.Ipv4.sin_addr, raw_addr, 4);
        }
        else
        {
            address_row.Address.Ipv6.sin6_family = AF_INET6;
            std::memcpy(&address_row.Address.Ipv6.sin6_addr, raw_addr, 16);
        }

        const DWORD result = CreateUnicastIpAddressEntry(&address_row);
        if (result != ERROR_SUCCESS && result != ERROR_OBJECT_ALREADY_EXISTS)
        {
            ec = {static_cast<int>(result), boost::system::system_category()};
            return false;
        }
        return true;
    };

    if (!cfg.ipv4.empty())
    {
        IN_ADDR addr4{};
        if (InetPtonA(AF_INET, cfg.ipv4.c_str(), &addr4) != 1)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
            return false;
        }
        if (!set_unicast_address(AF_INET, &addr4, cfg.ipv4_prefix))
        {
            return false;
        }
    }

    if (!cfg.ipv6.empty())
    {
        IN6_ADDR addr6{};
        if (InetPtonA(AF_INET6, cfg.ipv6.c_str(), &addr6) != 1)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
            return false;
        }
        if (!set_unicast_address(AF_INET6, &addr6, cfg.ipv6_prefix))
        {
            return false;
        }
    }

    return true;
#else
    if (!set_mtu(cfg.mtu, ec))
    {
        return false;
    }
    if (!cfg.ipv4.empty() && !set_ipv4(cfg.ipv4, cfg.ipv4_prefix, ec))
    {
        return false;
    }
    if (!cfg.ipv6.empty() && !set_ipv6(cfg.ipv6, cfg.ipv6_prefix, ec))
    {
        return false;
    }
    return set_state(true, ec);
#endif
}

void tun_device::close()
{
#ifdef _WIN32
    if (windows_ != nullptr)
    {
        if (windows_->session != nullptr && windows_->end_session != nullptr)
        {
            windows_->end_session(windows_->session);
        }
        if (windows_->adapter != nullptr && windows_->close_adapter != nullptr)
        {
            windows_->close_adapter(windows_->adapter);
        }
        if (windows_->module != nullptr)
        {
            FreeLibrary(windows_->module);
        }
        delete windows_;
        windows_ = nullptr;
    }
#else
    if (fd_ >= 0)
    {
        ::close(fd_);
        fd_ = -1;
    }
#endif
    name_.clear();
    index_.clear();
}

std::ptrdiff_t tun_device::read_packet(uint8_t* data, std::size_t capacity, boost::system::error_code& ec)
{
    ec.clear();

#ifdef _WIN32
    if (windows_ == nullptr || windows_->session == nullptr)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_file_descriptor);
        return -1;
    }

    DWORD packet_size = 0;
    BYTE* packet = windows_->receive_packet(windows_->session, &packet_size);
    if (packet == nullptr)
    {
        ec = win32_ec();
        if (ec.value() == ERROR_NO_MORE_ITEMS)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::resource_unavailable_try_again);
        }
        return -1;
    }

    const auto copy_size = std::min<std::size_t>(capacity, packet_size);
    std::memcpy(data, packet, copy_size);
    windows_->release_receive_packet(windows_->session, packet);
    if (copy_size != packet_size)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return -1;
    }
    return static_cast<std::ptrdiff_t>(copy_size);
#elif defined(__APPLE__) || defined(__MACH__)
#if TARGET_OS_OSX
    uint32_t family = 0;
    iovec iov[2] = {
        {.iov_base = &family, .iov_len = sizeof(family)},
        {.iov_base = data, .iov_len = capacity},
    };
    const auto n = ::readv(fd_, iov, 2);
    if (n < 0)
    {
        ec = errno_ec();
        return -1;
    }
    if (n <= static_cast<std::ptrdiff_t>(sizeof(family)))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return -1;
    }
    return n - static_cast<std::ptrdiff_t>(sizeof(family));
#else
    (void)data;
    (void)capacity;
    ec = boost::system::errc::make_error_code(boost::system::errc::not_supported);
    return -1;
#endif
#else
    const auto n = ::read(fd_, data, capacity);
    if (n < 0)
    {
        ec = errno_ec();
        return -1;
    }
    return n;
#endif
}

std::ptrdiff_t tun_device::write_packet(const uint8_t* data, std::size_t size, boost::system::error_code& ec)
{
    ec.clear();

#ifdef _WIN32
    if (windows_ == nullptr || windows_->session == nullptr)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_file_descriptor);
        return -1;
    }

    BYTE* packet = windows_->allocate_send_packet(windows_->session, static_cast<DWORD>(size));
    if (packet == nullptr)
    {
        ec = win32_ec();
        return -1;
    }
    std::memcpy(packet, data, size);
    windows_->send_packet(windows_->session, packet);
    return static_cast<std::ptrdiff_t>(size);
#elif defined(__APPLE__) || defined(__MACH__)
#if TARGET_OS_OSX
    const uint32_t family = htonl(((data[0] >> 4) & 0xF) == 4 ? AF_INET : AF_INET6);
    iovec iov[2] = {
        {.iov_base = const_cast<uint32_t*>(&family), .iov_len = sizeof(family)},
        {.iov_base = const_cast<uint8_t*>(data), .iov_len = size},
    };
    const auto n = ::writev(fd_, iov, 2);
    if (n < 0)
    {
        ec = errno_ec();
        return -1;
    }
    if (n <= static_cast<std::ptrdiff_t>(sizeof(family)))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::io_error);
        return -1;
    }
    return n - static_cast<std::ptrdiff_t>(sizeof(family));
#else
    (void)data;
    (void)size;
    ec = boost::system::errc::make_error_code(boost::system::errc::not_supported);
    return -1;
#endif
#else
    const auto n = ::write(fd_, data, size);
    if (n < 0)
    {
        ec = errno_ec();
        return -1;
    }
    return n;
#endif
}

#ifdef _WIN32
void* tun_device::read_wait_handle() const
{
    if (windows_ == nullptr || windows_->session == nullptr || windows_->get_read_wait_event == nullptr)
    {
        return nullptr;
    }
    return windows_->get_read_wait_event(windows_->session);
}
#else
bool tun_device::set_mtu(const uint32_t mtu, boost::system::error_code& ec)
{
    ec.clear();
    ifreq ifr{};
    ifr.ifr_mtu = static_cast<int>(mtu);
    std::strncpy(ifr.ifr_name, name_.c_str(), IFNAMSIZ - 1);

    const int socket_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0)
    {
        ec = errno_ec();
        return false;
    }

    const int ret = ::ioctl(socket_fd, SIOCSIFMTU, &ifr);
    const auto saved_errno = errno;
    ::close(socket_fd);
    if (ret != 0)
    {
        ec = {saved_errno, boost::system::system_category()};
        return false;
    }
    return true;
}

bool tun_device::set_state(const bool up, boost::system::error_code& ec)
{
    ec.clear();
    ifreq ifr{};
    std::strncpy(ifr.ifr_name, name_.c_str(), IFNAMSIZ - 1);

    const int socket_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0)
    {
        ec = errno_ec();
        return false;
    }

    if (::ioctl(socket_fd, SIOCGIFFLAGS, &ifr) != 0)
    {
        ec = errno_ec();
        ::close(socket_fd);
        return false;
    }

    if (up)
    {
        ifr.ifr_flags |= IFF_UP;
    }
    else
    {
        ifr.ifr_flags &= static_cast<short>(~IFF_UP);
    }

    if (::ioctl(socket_fd, SIOCSIFFLAGS, &ifr) != 0)
    {
        ec = errno_ec();
        ::close(socket_fd);
        return false;
    }

    ::close(socket_fd);
    return true;
}

bool tun_device::set_ipv4(const std::string& address, const uint8_t prefix, boost::system::error_code& ec)
{
    ec.clear();
    const int socket_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0)
    {
        ec = errno_ec();
        return false;
    }

#if defined(__linux__)
    ifreq ifr{};
    std::strncpy(ifr.ifr_name, name_.c_str(), IFNAMSIZ - 1);

    auto* addr = reinterpret_cast<sockaddr_in*>(&ifr.ifr_addr);
    addr->sin_family = AF_INET;
    if (::inet_pton(AF_INET, address.c_str(), &addr->sin_addr) != 1)
    {
        ::close(socket_fd);
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return false;
    }
    if (::ioctl(socket_fd, SIOCSIFADDR, &ifr) != 0)
    {
        ec = errno_ec();
        ::close(socket_fd);
        return false;
    }

    auto* mask = reinterpret_cast<sockaddr_in*>(&ifr.ifr_netmask);
    mask->sin_family = AF_INET;
    mask->sin_addr.s_addr = htonl(prefix_mask_v4(prefix));
    if (::ioctl(socket_fd, SIOCSIFNETMASK, &ifr) != 0 && errno != EEXIST)
    {
        ec = errno_ec();
        ::close(socket_fd);
        return false;
    }
#elif defined(__APPLE__) || defined(__MACH__)
#if TARGET_OS_OSX
    ifaliasreq ifra{};
    std::strncpy(ifra.ifra_name, name_.c_str(), IFNAMSIZ - 1);

    auto* addr = reinterpret_cast<sockaddr_in*>(&ifra.ifra_addr);
    addr->sin_len = sizeof(sockaddr_in);
    addr->sin_family = AF_INET;
    if (::inet_pton(AF_INET, address.c_str(), &addr->sin_addr) != 1)
    {
        ::close(socket_fd);
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return false;
    }
    std::memcpy(&ifra.ifra_broadaddr, &ifra.ifra_addr, sizeof(sockaddr_in));

    auto* mask = reinterpret_cast<sockaddr_in*>(&ifra.ifra_mask);
    mask->sin_len = sizeof(sockaddr_in);
    mask->sin_family = AF_INET;
    mask->sin_addr.s_addr = htonl(prefix_mask_v4(prefix));

    if (::ioctl(socket_fd, SIOCAIFADDR, &ifra) != 0)
    {
        ec = errno_ec();
        ::close(socket_fd);
        return false;
    }
#else
    (void)address;
    (void)prefix;
    ::close(socket_fd);
    ec = boost::system::errc::make_error_code(boost::system::errc::not_supported);
    return false;
#endif
#endif

    ::close(socket_fd);
    return true;
}

bool tun_device::set_ipv6(const std::string& address, const uint8_t prefix, boost::system::error_code& ec)
{
    ec.clear();

#if defined(__linux__)
    const int socket_fd = ::socket(AF_INET6, SOCK_DGRAM, 0);
    if (socket_fd < 0)
    {
        ec = errno_ec();
        return false;
    }

    ifreq ifr{};
    std::strncpy(ifr.ifr_name, name_.c_str(), IFNAMSIZ - 1);
    if (::ioctl(socket_fd, SIOCGIFINDEX, &ifr) != 0)
    {
        ec = errno_ec();
        ::close(socket_fd);
        return false;
    }

    in6_ifreq ifr6{};
    ifr6.ifr6_ifindex = ifr.ifr_ifindex;
    ifr6.ifr6_prefixlen = prefix;
    if (::inet_pton(AF_INET6, address.c_str(), &ifr6.ifr6_addr) != 1)
    {
        ::close(socket_fd);
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return false;
    }
    if (::ioctl(socket_fd, SIOCSIFADDR, &ifr6) != 0 && errno != EEXIST)
    {
        ec = errno_ec();
        ::close(socket_fd);
        return false;
    }

    ::close(socket_fd);
    return true;
#elif defined(__APPLE__) || defined(__MACH__)
#if TARGET_OS_OSX
    const int socket_fd = ::socket(AF_INET6, SOCK_DGRAM, 0);
    if (socket_fd < 0)
    {
        ec = errno_ec();
        return false;
    }

    in6_aliasreq ifra{};
    std::strncpy(ifra.ifra_name, name_.c_str(), IFNAMSIZ - 1);
    ifra.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
    ifra.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;
    ifra.ifra_addr.sin6_len = sizeof(sockaddr_in6);
    ifra.ifra_addr.sin6_family = AF_INET6;
    if (::inet_pton(AF_INET6, address.c_str(), &ifra.ifra_addr.sin6_addr) != 1)
    {
        ::close(socket_fd);
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return false;
    }

    ifra.ifra_prefixmask.sin6_len = sizeof(sockaddr_in6);
    ifra.ifra_prefixmask.sin6_family = AF_INET6;
    auto* mask_bytes = reinterpret_cast<uint8_t*>(&ifra.ifra_prefixmask.sin6_addr);
    std::fill(mask_bytes, mask_bytes + 16, 0);
    const auto full_bytes = static_cast<std::size_t>(prefix / 8U);
    const auto partial_bits = static_cast<uint8_t>(prefix % 8U);
    std::fill(mask_bytes, mask_bytes + full_bytes, 0xFF);
    if (full_bytes < 16 && partial_bits != 0)
    {
        mask_bytes[full_bytes] = static_cast<uint8_t>(0xFFU << (8U - partial_bits));
    }

    if (::ioctl(socket_fd, SIOCAIFADDR_IN6, &ifra) != 0)
    {
        ec = errno_ec();
        ::close(socket_fd);
        return false;
    }

    ::close(socket_fd);
    return true;
#else
    (void)address;
    (void)prefix;
    ec = boost::system::errc::make_error_code(boost::system::errc::not_supported);
    return false;
#endif
#else
    (void)address;
    (void)prefix;
    ec = boost::system::errc::make_error_code(boost::system::errc::not_supported);
    return false;
#endif
}
#endif

}    // namespace mux
