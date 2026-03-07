#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <utility>

#include <boost/asio/error.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "config.h"
#include "protocol.h"
#include "mux_codec.h"
#include "net_utils.h"
#include "statistics.h"
#include "timeout_io.h"
#include "scoped_exit.h"
#include "log_context.h"
#include "mux_protocol.h"
#include "remote_udp_session.h"

namespace mux
{

namespace
{

constexpr std::uint8_t kNoStreamControl = 0;

void update_stream_close_command(std::atomic<std::uint8_t>& stream_close_command, const std::uint8_t next_command)
{
    auto current = stream_close_command.load(std::memory_order_relaxed);
    for (;;)
    {
        std::uint8_t desired = current;
        if (next_command == mux::kCmdRst)
        {
            desired = mux::kCmdRst;
        }
        else if (next_command == kNoStreamControl && current != mux::kCmdRst)
        {
            desired = kNoStreamControl;
        }
        if (desired == current)
        {
            return;
        }
        if (stream_close_command.compare_exchange_weak(current, desired, std::memory_order_relaxed))
        {
            return;
        }
    }
}

[[nodiscard]] std::string endpoint_key_impl(const boost::asio::ip::udp::endpoint& endpoint)
{
    const auto normalized_endpoint = net::normalize_endpoint(endpoint);
    return normalized_endpoint.address().to_string() + ":" + std::to_string(normalized_endpoint.port());
}

}    // namespace

remote_udp_session::remote_udp_session(const std::shared_ptr<mux_connection>& connection,
                                       const std::uint32_t id,
                                       boost::asio::io_context& io_context,
                                       const connection_context& ctx,
                                       const config& cfg)
    : id_(id),
      cfg_(cfg),
      io_context_(io_context),
      timer_(io_context_),
      idle_timer_(io_context_),
      udp_socket_(io_context_),
      udp_resolver_(io_context_),
      stream_(std::make_shared<mux_stream>(id, cfg, io_context, connection)),
      connection_(connection)

{
    ctx_ = ctx;
    ctx_.stream_id(id);
    stream_close_command_.store(mux::kCmdFin, std::memory_order_relaxed);
    const auto ts = timeout_io::now_ms();
    last_read_time_ms_ = ts;
    last_write_time_ms_ = ts;
    last_activity_time_ms_ = ts;
    if (connection != nullptr)
    {
        connection->register_stream(stream_);
    }
}

boost::asio::awaitable<void> remote_udp_session::start()
{
    co_await boost::asio::dispatch(io_context_, boost::asio::use_awaitable);
    co_await start_impl();
}

boost::asio::awaitable<void> remote_udp_session::start_impl()
{
    DEFER(
        if (auto connection = connection_.lock(); connection != nullptr && stream_ != nullptr)
        {
            connection->remove_stream(stream_);
        });
    DEFER(
        boost::system::error_code ignore;
        ignore = udp_socket_.close(ignore);
        (void)ignore;);

    boost::system::error_code ec;
    const auto send_fail_ack = [&](const std::uint8_t rep) -> boost::asio::awaitable<void>
    {
        ack_payload ack{.socks_rep = rep, .bnd_addr = "0.0.0.0", .bnd_port = 0};
        std::vector<std::uint8_t> ack_data;
        if (!mux_codec::encode_ack(ack, ack_data))
        {
            co_return;
        }

        mux_frame ack_frame;
        ack_frame.h.stream_id = id_;
        ack_frame.h.command = mux::kCmdAck;
        ack_frame.payload = std::move(ack_data);
        boost::system::error_code ack_ec;
        co_await stream_->async_write(ack_frame, ack_ec);
    };

    auto bind_udp_socket = [&]() -> bool
    {
        ec = udp_socket_.open(boost::asio::ip::udp::v6(), ec);
        if (!ec)
        {
            ec = udp_socket_.set_option(boost::asio::ip::v6_only(false), ec);
            if (!ec)
            {
                ec = udp_socket_.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v6(), 0), ec);
            }
            if (!ec)
            {
                return true;
            }

            LOG_CTX_WARN(ctx_, "{} bind dual-stack udp failed {} fallback ipv4", log_event::kMux, ec.message());
            boost::system::error_code close_ec;
            close_ec = udp_socket_.close(close_ec);
        }
        else
        {
            LOG_CTX_WARN(ctx_, "{} open ipv6 udp failed {} fallback ipv4", log_event::kMux, ec.message());
        }

        ec = udp_socket_.open(boost::asio::ip::udp::v4(), ec);
        if (ec)
        {
            return false;
        }
        ec = udp_socket_.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 0), ec);
        return !ec;
    };

    if (!bind_udp_socket())
    {
        co_await send_fail_ack(socks::kRepGenFail);
        co_return;
    }

    boost::system::error_code local_ep_ec;
    const auto local_ep = udp_socket_.local_endpoint(local_ep_ec);
    if (local_ep_ec)
    {
        co_await send_fail_ack(socks::kRepGenFail);
        co_return;
    }
    const ack_payload ack{
        .socks_rep = socks::kRepSuccess,
        .bnd_addr = local_ep.address().to_string(),
        .bnd_port = local_ep.port(),
    };
    std::vector<std::uint8_t> ack_data;
    if (!mux_codec::encode_ack(ack, ack_data))
    {
        co_return;
    }
    mux_frame ack_frame;
    ack_frame.h.stream_id = id_;
    ack_frame.h.command = mux::kCmdAck;
    ack_frame.payload = std::move(ack_data);
    co_await stream_->async_write(ack_frame, ec);
    if (ec)
    {
        LOG_CTX_WARN(ctx_, "{} send ack failed {}", log_event::kMux, ec.message());
        co_return;
    }

    using boost::asio::experimental::awaitable_operators::operator||;
    co_await (mux_to_udp() || udp_to_mux() || idle_watchdog());

    const auto close_command = stream_close_command_.load(std::memory_order_relaxed);
    if (stream_ != nullptr && close_command != kNoStreamControl)
    {
        mux_frame close_frame;
        close_frame.h.stream_id = stream_->id();
        close_frame.h.command = close_command;
        boost::system::error_code close_ec;
        co_await stream_->async_write(std::move(close_frame), close_ec);
        if (close_ec)
        {
            LOG_CTX_WARN(ctx_,
                         "{} send {} failed {}",
                         log_event::kMux,
                         close_command == mux::kCmdRst ? "rst" : "fin",
                         close_ec.message());
        }
    }

    LOG_CTX_INFO(ctx_, "{} finished {}", log_event::kConnClose, ctx_.stats_summary());
}

boost::asio::awaitable<void> remote_udp_session::watchdog()
{
    const auto read_timeout_ms = static_cast<std::uint64_t>(cfg_.timeout.read) * 1000ULL;
    const auto write_timeout_ms = static_cast<std::uint64_t>(cfg_.timeout.write) * 1000ULL;
    while (udp_socket_.is_open())
    {
        timer_.expires_after(std::chrono::seconds(1));
        const auto [wait_ec] = co_await timer_.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (wait_ec)
        {
            if (wait_ec == boost::asio::error::operation_aborted)
            {
                LOG_CTX_DEBUG(ctx_, "{} watchdog stopped {}", log_event::kTimeout, wait_ec.message());
            }
            else
            {
                LOG_CTX_WARN(ctx_, "{} watchdog error {}", log_event::kTimeout, wait_ec.message());
            }
            break;
        }
        const auto current_ms = timeout_io::now_ms();
        const auto read_elapsed_ms = current_ms - last_read_time_ms_;
        const auto write_elapsed_ms = current_ms - last_write_time_ms_;
        if (read_timeout_ms > 0 && read_elapsed_ms > read_timeout_ms)
        {
            LOG_CTX_WARN(ctx_, "{} read idle {}s", log_event::kTimeout, read_elapsed_ms / 1000ULL);
            break;
        }
        if (write_timeout_ms > 0 && write_elapsed_ms > write_timeout_ms)
        {
            LOG_CTX_WARN(ctx_, "{} write idle {}s", log_event::kTimeout, write_elapsed_ms / 1000ULL);
            break;
        }
    }
    LOG_CTX_DEBUG(ctx_, "{} watchdog finished", log_event::kMux);
}

boost::asio::awaitable<void> remote_udp_session::mux_to_udp()
{
    boost::system::error_code ec;
    for (;;)
    {
        const auto data_frame = co_await stream_->async_read(ec);
        if (ec)
        {
            update_stream_close_command(stream_close_command_, kNoStreamControl);
            break;
        }
        if (data_frame.h.command == mux::kCmdRst || data_frame.h.command == mux::kCmdFin)
        {
            update_stream_close_command(stream_close_command_, kNoStreamControl);
            break;
        }
        if (data_frame.h.command != mux::kCmdDat)
        {
            update_stream_close_command(stream_close_command_, mux::kCmdRst);
            ec = boost::asio::error::invalid_argument;
            break;
        }
        co_await on_frame(data_frame, ec);
        if (ec)
        {
            if (ec == boost::asio::error::invalid_argument || ec == boost::system::errc::make_error_code(boost::system::errc::bad_message))
            {
                update_stream_close_command(stream_close_command_, mux::kCmdRst);
            }
            else
            {
                update_stream_close_command(stream_close_command_, kNoStreamControl);
            }
            break;
        }
    }
    LOG_CTX_INFO(ctx_, "{} mux_to_udp finished", log_event::kMux);
}

boost::asio::awaitable<void> remote_udp_session::on_frame(const mux_frame& frame, boost::system::error_code& ec)
{
    socks_udp_header header;
    if (!socks_codec::decode_udp_header(frame.payload.data(), frame.payload.size(), header))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        LOG_CTX_WARN(ctx_, "{} stage=decode_header error=invalid_udp_header", log_event::kMux);
        co_return;
    }
    if (header.frag != 0x00)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        LOG_CTX_WARN(ctx_, "{} stage=decode_header error=unsupported_frag frag={}", log_event::kMux, header.frag);
        co_return;
    }
    if (header.addr.empty())
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        LOG_CTX_WARN(ctx_, "{} stage=decode_header error=empty_target_host", log_event::kMux);
        co_return;
    }
    if (header.port == 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        LOG_CTX_WARN(ctx_, "{} stage=decode_header error=invalid_target_port", log_event::kMux);
        co_return;
    }

    if (header.header_len > frame.payload.size())
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        LOG_CTX_WARN(ctx_,
                     "{} stage=decode_header error=invalid_header_len header_len={} packet_len={}",
                     log_event::kMux,
                     header.header_len,
                     frame.payload.size());
        co_return;
    }

    boost::system::error_code resolve_ec;
    auto res = co_await timeout_io::wait_resolve_with_timeout(
        udp_resolver_, header.addr, std::to_string(header.port), cfg_.timeout.connect, resolve_ec);
    if (resolve_ec)
    {
        statistics::instance().inc_remote_udp_session_resolve_errors();
        LOG_CTX_WARN(ctx_, "{} stage=resolve target={}:{} error={}", log_event::kMux, header.addr, header.port, resolve_ec.message());
        ec.clear();
        co_return;
    }
    if (res.begin() == res.end())
    {
        LOG_CTX_WARN(ctx_, "{} stage=resolve target={}:{} error=empty_result", log_event::kMux, header.addr, header.port);
        co_return;
    }

    auto target_ep = net::normalize_endpoint(res.begin()->endpoint());
    const auto payload_len = frame.payload.size() - header.header_len;
    LOG_CTX_DEBUG(ctx_, "{} udp forwarding {} bytes to {}", log_event::kMux, payload_len, target_ep.address().to_string());
    co_await udp_socket_.async_send_to(boost::asio::buffer(frame.payload.data() + header.header_len, payload_len),
                                       target_ep,
                                       boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec)
    {
        LOG_CTX_WARN(ctx_, "{} stage=send target={}:{} error={}", log_event::kMux, target_ep.address().to_string(), target_ep.port(), ec.message());
        co_return;
    }
    const auto ts = timeout_io::now_ms();
    last_write_time_ms_ = ts;
    last_activity_time_ms_ = ts;
    ctx_.add_tx_bytes(payload_len);
    allowed_reply_peers_.insert(endpoint_key(target_ep));
}

boost::asio::awaitable<void> remote_udp_session::udp_to_mux()
{
    std::vector<std::uint8_t> buf(65535);
    boost::asio::ip::udp::endpoint ep;
    boost::system::error_code ec;
    for (;;)
    {
        auto n = co_await udp_socket_.async_receive_from(boost::asio::buffer(buf), ep, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec)
        {
            LOG_CTX_WARN(ctx_, "{} udp receive error {}", log_event::kMux, ec.message());
            break;
        }

        LOG_CTX_DEBUG(ctx_, "{} udp recv {} bytes from {}", log_event::kMux, n, ep.address().to_string());
        const auto normalized_ep = net::normalize_endpoint(ep);
        if (!allowed_reply_peers_.contains(endpoint_key(normalized_ep)))
        {
            LOG_CTX_WARN(ctx_,
                         "{} ignore udp packet from unexpected peer {}:{}",
                         log_event::kMux,
                         normalized_ep.address().to_string(),
                         normalized_ep.port());
            continue;
        }

        const auto ts = timeout_io::now_ms();
        last_read_time_ms_ = ts;
        last_activity_time_ms_ = ts;
        ctx_.add_rx_bytes(n);
        socks_udp_header h;
        h.addr = normalized_ep.address().to_string();
        h.port = normalized_ep.port();
        auto header_bytes = socks_codec::encode_udp_header(h);

        std::vector<std::uint8_t> pkt;
        pkt.reserve(header_bytes.size() + n);
        pkt.insert(pkt.end(), header_bytes.begin(), header_bytes.end());
        pkt.insert(pkt.end(), buf.begin(), buf.begin() + static_cast<std::uint32_t>(n));
        const auto pkt_size = pkt.size();
        if (pkt_size > mux::kMaxPayload)
        {
            LOG_CTX_WARN(ctx_, "{} drop oversized udp packet size {} max {}", log_event::kMux, pkt_size, mux::kMaxPayload);
            continue;
        }
        mux_frame data_frame;
        data_frame.h.stream_id = id_;
        data_frame.h.command = kCmdDat;
        data_frame.payload = std::move(pkt);
        co_await stream_->async_write(data_frame, ec);
        if (ec)
        {
            LOG_CTX_WARN(ctx_, "{} send udp packet to mux failed {}", log_event::kMux, ec.message());
            break;
        }
        const auto write_ts = timeout_io::now_ms();
        last_write_time_ms_ = write_ts;
        last_activity_time_ms_ = write_ts;
        ctx_.add_tx_bytes(pkt_size);
    }
    LOG_CTX_DEBUG(ctx_, "{} udp recv loop stopped", log_event::kMux);
}

std::string remote_udp_session::endpoint_key(const boost::asio::ip::udp::endpoint& endpoint)
{
    return endpoint_key_impl(endpoint);
}

boost::asio::awaitable<void> remote_udp_session::idle_watchdog()
{
    if (cfg_.timeout.idle == 0)
    {
        co_return;
    }
    auto idle_timeout_ms = static_cast<std::uint64_t>(cfg_.timeout.idle) * 1000ULL;
    while (udp_socket_.is_open())
    {
        idle_timer_.expires_after(std::chrono::seconds(1));
        const auto [ec] = co_await idle_timer_.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec)
        {
            break;
        }
        const auto current_ms = timeout_io::now_ms();
        const auto elapsed_ms = current_ms - last_activity_time_ms_;
        if (elapsed_ms > idle_timeout_ms)
        {
            LOG_CTX_WARN(ctx_, "{} udp session idle closing", log_event::kMux);
            break;
        }
    }
    LOG_CTX_DEBUG(ctx_, "{} idle watchdog stopped", log_event::kMux);
}

}    // namespace mux
