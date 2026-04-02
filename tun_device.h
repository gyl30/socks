#ifndef TUN_DEVICE_H
#define TUN_DEVICE_H

#include <string>
#include <cstddef>
#include <cstdint>

#include <boost/system/error_code.hpp>

#include "config.h"
namespace mux
{

class tun_device
{
   public:
    tun_device() = default;
    ~tun_device();

    tun_device(const tun_device&) = delete;
    tun_device& operator=(const tun_device&) = delete;

    [[nodiscard]] bool open(const config::tun_t& cfg, boost::system::error_code& ec);
    void close();

    [[nodiscard]] std::ptrdiff_t read_packet(uint8_t* data, std::size_t capacity, boost::system::error_code& ec);
    [[nodiscard]] std::ptrdiff_t write_packet(const uint8_t* data, std::size_t size, boost::system::error_code& ec);

    [[nodiscard]] const std::string& name() const { return name_; }
    [[nodiscard]] const std::string& index() const { return index_; }

#ifdef _WIN32
    [[nodiscard]] void* read_wait_handle() const;
#else
    [[nodiscard]] int native_handle() const { return fd_; }
#endif

   private:
    [[nodiscard]] bool configure(const config::tun_t& cfg, boost::system::error_code& ec);

#ifndef _WIN32
    [[nodiscard]] bool set_mtu(uint32_t mtu, boost::system::error_code& ec);
    [[nodiscard]] bool set_state(bool up, boost::system::error_code& ec);
    [[nodiscard]] bool set_ipv4(const std::string& address, uint8_t prefix, boost::system::error_code& ec);
    [[nodiscard]] bool set_ipv6(const std::string& address, uint8_t prefix, boost::system::error_code& ec);
#endif

   private:
    std::string name_;
    std::string index_;

#ifdef _WIN32
    struct windows_state;
    windows_state* windows_ = nullptr;
#else
    int fd_ = -1;
#endif
};

}    // namespace mux

#endif
