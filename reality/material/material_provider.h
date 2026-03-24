#ifndef REALITY_MATERIAL_PROVIDER_H
#define REALITY_MATERIAL_PROVIDER_H

#include <string>
#include <utility>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <functional>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>

#include "cert_manager.h"
#include "site_material.h"

namespace mux
{

struct config;

}    // namespace mux

namespace reality
{

class material_provider
{
   public:
    struct options
    {
        std::uint16_t fallback_port = 443;
        std::uint32_t fetch_success_ttl_sec = 6 * 60 * 60;
        std::uint32_t fetch_failure_retry_sec = 5 * 60;
        std::size_t cache_capacity = 4;
    };

    struct fetch_request
    {
        std::string host;
        std::uint16_t port = 0;
        std::string sni;
        std::string trace_id;
        std::uint32_t connect_timeout_sec = 0;
        std::uint32_t read_timeout_sec = 0;
        std::uint32_t write_timeout_sec = 0;
    };

    struct fetch_reply
    {
        std::optional<site_material> material;
        std::string error_stage;
        std::string error_reason;
    };

    struct refresh_result
    {
        bool attempted = false;
        bool success = false;
        std::uint32_t next_refresh_in_seconds = 0;
    };

    using fetch_operation = std::function<boost::asio::awaitable<fetch_reply>(boost::asio::io_context&, fetch_request)>;

    struct dependencies
    {
        const mux::config& cfg;
        options opts{};
        std::function<std::uint64_t()> now_seconds;
        fetch_operation fetch;
    };

    explicit material_provider(dependencies deps);
    ~material_provider();

    material_provider(const material_provider&) = delete;
    material_provider& operator=(const material_provider&) = delete;

    [[nodiscard]] std::optional<site_material_snapshot> get_server_material_snapshot();

    [[nodiscard]] boost::asio::awaitable<refresh_result> refresh_once(boost::asio::io_context& io_context);
    [[nodiscard]] boost::asio::awaitable<void> refresh_loop(boost::asio::io_context& io_context);

   private:
    [[nodiscard]] std::uint64_t now_seconds() const;

    const mux::config& cfg_;
    options options_{};
    std::function<std::uint64_t()> now_seconds_fn_;
    fetch_operation fetch_;
    site_material_manager manager_;
};

}    // namespace reality

#endif
