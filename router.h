#ifndef ROUTER_H
#define ROUTER_H

#include <memory>
#include <string>
#include <asio.hpp>
#include "log.h"
#include "ip_matcher.h"
#include "domain_matcher.h"

namespace mux
{

enum class route_type : uint8_t
{
    direct,
    proxy,
    block
};

class router
{
   public:
    router(std::shared_ptr<ip_matcher> ip_m, std::shared_ptr<domain_matcher> domain_m)
        : ip_matcher_(std::move(ip_m)), domain_matcher_(std::move(domain_m))
    {
    }

    [[nodiscard]] asio::awaitable<route_type> decide(const std::string& host, const asio::any_io_executor& ex) const
    {
        bool force_proxy = false;
        std::error_code ec;
        auto addr = asio::ip::make_address(host, ec);
        bool is_domain = false;
        if (ec)
        {
            LOG_WARN("parse {} to host failed {}", host, ec.message());
            is_domain = true;
        }

        if (is_domain && domain_matcher_)
        {
            if (domain_matcher_->match(host))
            {
                LOG_INFO("matched domain rule force proxy host {}", host);
                force_proxy = true;
            }
        }

        if (!force_proxy && ip_matcher_)
        {
            if (!is_domain)
            {
                if (ip_matcher_->match(addr))
                {
                    LOG_INFO("matched ip rule direct host {}", host);
                    co_return route_type::direct;
                }
            }
            else
            {
                asio::ip::tcp::resolver resolver(ex);
                auto [res_ec, eps] = co_await resolver.async_resolve(host, "", asio::as_tuple(asio::use_awaitable));
                if (res_ec)
                {
                    LOG_ERROR("resolve domain {} error {}", host, res_ec.message());
                    co_return route_type::proxy;
                }

                for (const auto& ep : eps)
                {
                    if (ip_matcher_->match(ep.endpoint().address()))
                    {
                        LOG_INFO("matched resolve ip rule direct host {} ip {}", host, ep.endpoint().address().to_string());
                        co_return route_type::direct;
                    }
                }
            }
        }

        co_return route_type::proxy;
    }

   private:
    std::shared_ptr<ip_matcher> ip_matcher_;
    std::shared_ptr<domain_matcher> domain_matcher_;
};

}    // namespace mux

#endif
