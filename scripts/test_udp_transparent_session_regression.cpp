#include <chrono>
#include <array>
#include <cstdint>
#include <future>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/udp.hpp>

#include "config.h"
#include "context_pool.h"
#include "protocol.h"
#include "router.h"
#include "tproxy_udp_session.h"
#include "trace_store.h"
#include "tun_lwip.h"
#include "tun_udp_session.h"

namespace
{

using namespace std::chrono_literals;

using test_result = std::optional<std::string>;

[[nodiscard]] test_result fail_test(std::string message)
{
    return test_result(std::move(message));
}

#define TEST_RETURN_IF_ERROR(expr)         \
    do                                     \
    {                                      \
        if (auto _error = (expr); _error)  \
        {                                  \
            return _error;                 \
        }                                  \
    } while (false)

#define TEST_CHECK(condition, message) \
    do                                 \
    {                                  \
        if (!(condition))              \
        {                              \
            return fail_test(message); \
        }                              \
    } while (false)

template <typename T, typename Awaitable>
[[nodiscard]] test_result wait_awaitable_result(boost::asio::io_context& io_context, Awaitable awaitable, T& value, std::string_view label)
{
    struct completion_state
    {
        bool failed = false;
        T value{};
    };

    std::promise<completion_state> promise;
    auto future = promise.get_future();
    boost::asio::co_spawn(
        io_context,
        std::move(awaitable),
        [&promise](std::exception_ptr ex, T result)
        {
            completion_state state;
            state.failed = (ex != nullptr);
            state.value = std::move(result);
            promise.set_value(std::move(state));
        });

    const auto state = future.get();
    if (state.failed)
    {
        return fail_test(std::string(label) + " awaitable failed");
    }
    value = state.value;
    return std::nullopt;
}

[[nodiscard]] test_result expect_enqueue_result(boost::asio::io_context& io_context,
                                                boost::asio::awaitable<relay::udp_enqueue_result> awaitable,
                                                const relay::udp_enqueue_result expected,
                                                const std::string& failure_message)
{
    relay::udp_enqueue_result result = relay::udp_enqueue_result::kClosed;
    TEST_RETURN_IF_ERROR(wait_awaitable_result(io_context, std::move(awaitable), result, failure_message));
    TEST_CHECK(result == expected, failure_message);
    return std::nullopt;
}

[[nodiscard]] test_result build_router(const relay::config& cfg,
                                       std::string_view inbound_tag,
                                       std::shared_ptr<relay::router>& route)
{
    auto shared_state = relay::router::build_shared_state(cfg);
    TEST_CHECK(shared_state != nullptr, "failed to build router state for " + std::string(inbound_tag));
    route = std::make_shared<relay::router>(std::move(shared_state), std::string(inbound_tag));
    return std::nullopt;
}

class io_worker_runtime
{
   public:
    io_worker_runtime()
        : work_guard_(boost::asio::make_work_guard(worker_.io_context)),
          thread_([this]() { worker_.io_context.run(); })
    {
    }

    ~io_worker_runtime()
    {
        work_guard_.reset();
        worker_.io_context.stop();
        if (thread_.joinable())
        {
            thread_.join();
        }
    }

    relay::io_worker& worker() { return worker_; }

    [[nodiscard]] test_result wait_until_idle()
    {
        boost::system::error_code ec;
        TEST_RETURN_IF_ERROR(wait_awaitable_result(worker_.io_context, worker_.group.async_wait(), ec, "wait task group"));
        TEST_CHECK(!ec, "wait task group failed: " + ec.message());
        return std::nullopt;
    }

   private:
    relay::io_worker worker_;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work_guard_;
    std::thread thread_;
};

class lwip_udp_pcb_holder
{
   public:
    lwip_udp_pcb_holder() : pcb_(udp_new_ip_type(IPADDR_TYPE_ANY)) {}

    lwip_udp_pcb_holder(const lwip_udp_pcb_holder&) = delete;
    lwip_udp_pcb_holder& operator=(const lwip_udp_pcb_holder&) = delete;

    ~lwip_udp_pcb_holder()
    {
        if (pcb_ != nullptr)
        {
            udp_recv(pcb_, nullptr, nullptr);
            udp_remove(pcb_);
        }
    }

    [[nodiscard]] bool valid() const { return pcb_ != nullptr; }

    udp_pcb* release()
    {
        auto* pcb = pcb_;
        pcb_ = nullptr;
        return pcb;
    }

   private:
    udp_pcb* pcb_ = nullptr;
};

class udp_blackhole_server
{
   public:
    udp_blackhole_server()
        : socket_(io_context_, boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0))
    {
    }

    [[nodiscard]] boost::asio::ip::udp::endpoint endpoint() const { return socket_.local_endpoint(); }

   private:
    boost::asio::io_context io_context_;
    boost::asio::ip::udp::socket socket_;
};

class fake_socks_udp_server
{
   public:
    explicit fake_socks_udp_server(const int expected_sessions = 1)
        : acceptor_(io_context_, boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0)),
          udp_socket_(io_context_, boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0)),
          expected_sessions_(expected_sessions),
          thread_([this]() { serve(); })
    {
    }

    ~fake_socks_udp_server()
    {
        stop();
        if (thread_.joinable())
        {
            thread_.join();
        }
    }

    [[nodiscard]] uint16_t tcp_port() const { return acceptor_.local_endpoint().port(); }

    [[nodiscard]] test_result join()
    {
        if (thread_.joinable())
        {
            thread_.join();
        }
        if (server_error_.has_value())
        {
            return fail_test(*server_error_);
        }
        return std::nullopt;
    }

   private:
    void stop()
    {
        boost::system::error_code ec;
        acceptor_.close(ec);
        udp_socket_.close(ec);
    }

    void serve()
    {
        for (int i = 0; i < expected_sessions_; ++i)
        {
            boost::system::error_code ec;
            boost::asio::ip::tcp::socket tcp_socket(io_context_);
            acceptor_.accept(tcp_socket, ec);
            if (ec)
            {
                server_error_ = "accept failed: " + ec.message();
                return;
            }

            std::array<uint8_t, 3> method_request{};
            boost::asio::read(tcp_socket, boost::asio::buffer(method_request), ec);
            if (ec)
            {
                server_error_ = "read method_request failed: " + ec.message();
                return;
            }

            const std::array<uint8_t, 2> method_reply{{socks::kVer, socks::kMethodNoAuth}};
            boost::asio::write(tcp_socket, boost::asio::buffer(method_reply), ec);
            if (ec)
            {
                server_error_ = "write method_reply failed: " + ec.message();
                return;
            }

            std::array<uint8_t, 10> udp_associate_request{};
            boost::asio::read(tcp_socket, boost::asio::buffer(udp_associate_request), ec);
            if (ec)
            {
                server_error_ = "read udp_associate_request failed: " + ec.message();
                return;
            }

            const auto udp_endpoint = udp_socket_.local_endpoint();
            const auto udp_associate_reply = socks::make_reply(socks::kRepSuccess, udp_endpoint.address(), udp_endpoint.port());
            boost::asio::write(tcp_socket, boost::asio::buffer(udp_associate_reply), ec);
            if (ec)
            {
                server_error_ = "write udp_associate_reply failed: " + ec.message();
                return;
            }

            std::array<uint8_t, 4096> packet{};
            boost::asio::ip::udp::endpoint sender;
            udp_socket_.receive_from(boost::asio::buffer(packet), sender, 0, ec);
            if (ec)
            {
                server_error_ = "receive udp packet failed: " + ec.message();
                return;
            }

            const std::array<uint8_t, 3> malformed_reply{{0x00, 0x00, 0x00}};
            udp_socket_.send_to(boost::asio::buffer(malformed_reply), sender, 0, ec);
            if (ec)
            {
                server_error_ = "send malformed_reply failed: " + ec.message();
                return;
            }
        }
    }

   private:
    boost::asio::io_context io_context_;
    boost::asio::ip::tcp::acceptor acceptor_;
    boost::asio::ip::udp::socket udp_socket_;
    int expected_sessions_ = 1;
    std::thread thread_;
    std::optional<std::string> server_error_;
};

relay::config make_route_blocked_config()
{
    relay::config cfg;
    cfg.workers = 1;
    cfg.timeout.read = 5;
    cfg.timeout.write = 5;
    cfg.timeout.connect = 5;
    cfg.timeout.idle = 5;

    relay::config::outbound_entry_t direct_outbound;
    direct_outbound.type = "direct";
    direct_outbound.tag = "direct";
    cfg.outbounds.push_back(direct_outbound);

    relay::config::outbound_entry_t block_outbound;
    block_outbound.type = "block";
    block_outbound.tag = "block";
    cfg.outbounds.push_back(block_outbound);

    relay::config::route_rule_t tproxy_rule;
    tproxy_rule.type = "inbound";
    tproxy_rule.values = {"tproxy-in"};
    tproxy_rule.out = "block";
    cfg.routing.push_back(std::move(tproxy_rule));

    relay::config::route_rule_t tun_rule;
    tun_rule.type = "inbound";
    tun_rule.values = {"tun-in"};
    tun_rule.out = "block";
    cfg.routing.push_back(std::move(tun_rule));

    return cfg;
}

relay::config make_direct_config(const uint32_t idle_timeout_sec)
{
    relay::config cfg;
    cfg.workers = 1;
    cfg.timeout.read = 5;
    cfg.timeout.write = 5;
    cfg.timeout.connect = 5;
    cfg.timeout.idle = idle_timeout_sec;

    relay::config::outbound_entry_t direct_outbound;
    direct_outbound.type = "direct";
    direct_outbound.tag = "direct";
    cfg.outbounds.push_back(direct_outbound);

    relay::config::route_rule_t tproxy_rule;
    tproxy_rule.type = "inbound";
    tproxy_rule.values = {"tproxy-in"};
    tproxy_rule.out = "direct";
    cfg.routing.push_back(std::move(tproxy_rule));

    relay::config::route_rule_t tun_rule;
    tun_rule.type = "inbound";
    tun_rule.values = {"tun-in"};
    tun_rule.out = "direct";
    cfg.routing.push_back(std::move(tun_rule));

    return cfg;
}

relay::config make_proxy_fail_config(const uint16_t socks_port)
{
    relay::config cfg;
    cfg.workers = 1;
    cfg.timeout.read = 2;
    cfg.timeout.write = 2;
    cfg.timeout.connect = 1;
    cfg.timeout.idle = 5;

    relay::config::outbound_entry_t socks_outbound;
    socks_outbound.type = "socks";
    socks_outbound.tag = "socks-out";
    socks_outbound.socks = relay::config::socks_t{};
    socks_outbound.socks->host = "127.0.0.1";
    socks_outbound.socks->port = socks_port;
    socks_outbound.socks->auth = false;
    cfg.outbounds.push_back(std::move(socks_outbound));

    relay::config::route_rule_t tproxy_rule;
    tproxy_rule.type = "inbound";
    tproxy_rule.values = {"tproxy-in"};
    tproxy_rule.out = "socks-out";
    cfg.routing.push_back(std::move(tproxy_rule));

    relay::config::route_rule_t tun_rule;
    tun_rule.type = "inbound";
    tun_rule.values = {"tun-in"};
    tun_rule.out = "socks-out";
    cfg.routing.push_back(std::move(tun_rule));

    return cfg;
}

relay::config make_proxy_config(const uint16_t socks_port)
{
    relay::config cfg;
    cfg.workers = 1;
    cfg.timeout.read = 2;
    cfg.timeout.write = 2;
    cfg.timeout.connect = 2;
    cfg.timeout.idle = 10;

    relay::config::outbound_entry_t socks_outbound;
    socks_outbound.type = "socks";
    socks_outbound.tag = "socks-out";
    socks_outbound.socks = relay::config::socks_t{};
    socks_outbound.socks->host = "127.0.0.1";
    socks_outbound.socks->port = socks_port;
    socks_outbound.socks->auth = false;
    cfg.outbounds.push_back(std::move(socks_outbound));

    relay::config::route_rule_t tproxy_rule;
    tproxy_rule.type = "inbound";
    tproxy_rule.values = {"tproxy-in"};
    tproxy_rule.out = "socks-out";
    cfg.routing.push_back(std::move(tproxy_rule));

    relay::config::route_rule_t tun_rule;
    tun_rule.type = "inbound";
    tun_rule.values = {"tun-in"};
    tun_rule.out = "socks-out";
    cfg.routing.push_back(std::move(tun_rule));

    return cfg;
}

relay::config make_multi_proxy_config(const uint16_t socks_a_port, const uint16_t socks_b_port)
{
    relay::config cfg;
    cfg.workers = 1;
    cfg.timeout.read = 2;
    cfg.timeout.write = 2;
    cfg.timeout.connect = 2;
    cfg.timeout.idle = 10;

    relay::config::outbound_entry_t socks_a;
    socks_a.type = "socks";
    socks_a.tag = "socks-out-a";
    socks_a.socks = relay::config::socks_t{};
    socks_a.socks->host = "127.0.0.1";
    socks_a.socks->port = socks_a_port;
    socks_a.socks->auth = false;
    cfg.outbounds.push_back(std::move(socks_a));

    relay::config::outbound_entry_t socks_b;
    socks_b.type = "socks";
    socks_b.tag = "socks-out-b";
    socks_b.socks = relay::config::socks_t{};
    socks_b.socks->host = "127.0.0.1";
    socks_b.socks->port = socks_b_port;
    socks_b.socks->auth = false;
    cfg.outbounds.push_back(std::move(socks_b));

    relay::config::route_rule_t first_target;
    first_target.type = "ip";
    first_target.values = {"127.0.0.2/32"};
    first_target.out = "socks-out-a";
    cfg.routing.push_back(std::move(first_target));

    relay::config::route_rule_t second_target;
    second_target.type = "ip";
    second_target.values = {"127.0.0.3/32"};
    second_target.out = "socks-out-b";
    cfg.routing.push_back(std::move(second_target));

    return cfg;
}

[[nodiscard]] test_result require_single_trace(const std::string& inbound_tag, relay::trace_session_snapshot& snapshot)
{
    relay::trace_query query;
    query.inbound_tag = inbound_tag;
    query.limit = 10;

    const auto items = relay::trace_store::instance().list_traces(query);
    TEST_CHECK(items.size() == 1, "unexpected trace count for " + inbound_tag + ": " + std::to_string(items.size()));

    const auto trace = relay::trace_store::instance().get_trace(items.front().trace_id);
    TEST_CHECK(trace.has_value(), "trace snapshot missing for " + inbound_tag);
    snapshot = *trace;
    return std::nullopt;
}

[[nodiscard]] test_result require_trace_by_conn_id(const std::string& inbound_tag,
                                                   const uint32_t conn_id,
                                                   relay::trace_session_snapshot& snapshot)
{
    relay::trace_query query;
    query.inbound_tag = inbound_tag;
    query.limit = 20;

    const auto items = relay::trace_store::instance().list_traces(query);
    for (const auto& item : items)
    {
        if (item.conn_id != conn_id)
        {
            continue;
        }
        const auto trace = relay::trace_store::instance().get_trace(item.trace_id);
        TEST_CHECK(trace.has_value(), "trace snapshot missing for " + inbound_tag + " conn " + std::to_string(conn_id));
        snapshot = *trace;
        return std::nullopt;
    }

    return fail_test("trace not found for " + inbound_tag + " conn " + std::to_string(conn_id));
}

const relay::trace_event* find_event(const relay::trace_session_snapshot& snapshot, const relay::trace_stage stage)
{
    for (const auto& event : snapshot.events)
    {
        if (event.stage == stage)
        {
            return &event;
        }
    }
    return nullptr;
}

[[nodiscard]] test_result wait_for_trace_stage(const std::string& inbound_tag,
                                               const uint32_t conn_id,
                                               const relay::trace_stage stage,
                                               std::string_view label)
{
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (std::chrono::steady_clock::now() < deadline)
    {
        relay::trace_session_snapshot snapshot;
        if (!require_trace_by_conn_id(inbound_tag, conn_id, snapshot).has_value() && find_event(snapshot, stage) != nullptr)
        {
            return std::nullopt;
        }
        std::this_thread::sleep_for(20ms);
    }

    return fail_test("timeout waiting trace stage for " + std::string(label));
}

[[nodiscard]] test_result expect_route_blocked_trace(const relay::trace_session_snapshot& snapshot, std::string_view inbound_type)
{
    const auto& summary = snapshot.summary;
    TEST_CHECK(summary.status == relay::trace_status::kFailed, "unexpected trace status for " + std::string(inbound_type));
    TEST_CHECK(summary.inbound_type == inbound_type, "unexpected inbound_type for " + std::string(inbound_type) + ": " + summary.inbound_type);
    TEST_CHECK(summary.route_type == "block", "unexpected route_type for " + std::string(inbound_type) + ": " + summary.route_type);
    TEST_CHECK(summary.lifecycle.route_decide_done, "route_decide_done missing for " + std::string(inbound_type));
    TEST_CHECK(summary.lifecycle.session_error, "session_error missing for " + std::string(inbound_type));
    TEST_CHECK(!summary.lifecycle.session_close, "unexpected session_close for " + std::string(inbound_type));

    const auto* route_done = find_event(snapshot, relay::trace_stage::kRouteDecideDone);
    TEST_CHECK(route_done != nullptr && route_done->result == relay::trace_result::kFail,
               "route_decide_done trace mismatch for " + std::string(inbound_type));

    const auto* session_error = find_event(snapshot, relay::trace_stage::kSessionError);
    TEST_CHECK(session_error != nullptr, "session_error event missing for " + std::string(inbound_type));
    const auto close_reason_it = session_error->extra.find("close_reason");
    TEST_CHECK(close_reason_it != session_error->extra.end() && close_reason_it->second == "route_blocked",
               "unexpected close_reason for " + std::string(inbound_type));
    TEST_CHECK(session_error->error_message == "route blocked",
               "unexpected error_message for " + std::string(inbound_type) + ": " + session_error->error_message);

    TEST_CHECK(find_event(snapshot, relay::trace_stage::kSessionClose) == nullptr,
               "unexpected session_close event for " + std::string(inbound_type));
    return std::nullopt;
}

[[nodiscard]] test_result expect_idle_timeout_trace(const relay::trace_session_snapshot& snapshot, std::string_view inbound_type)
{
    const auto& summary = snapshot.summary;
    TEST_CHECK(summary.status == relay::trace_status::kSuccess, "unexpected trace status for " + std::string(inbound_type));
    TEST_CHECK(summary.inbound_type == inbound_type, "unexpected inbound_type for " + std::string(inbound_type) + ": " + summary.inbound_type);
    TEST_CHECK(summary.route_type == "direct", "unexpected route_type for " + std::string(inbound_type) + ": " + summary.route_type);
    TEST_CHECK(summary.lifecycle.route_decide_done, "route_decide_done missing for " + std::string(inbound_type));
    TEST_CHECK(summary.lifecycle.outbound_connect_done, "outbound_connect_done missing for " + std::string(inbound_type));
    TEST_CHECK(summary.lifecycle.session_close, "session_close missing for " + std::string(inbound_type));
    TEST_CHECK(!summary.lifecycle.session_error, "unexpected session_error for " + std::string(inbound_type));

    const auto* session_close = find_event(snapshot, relay::trace_stage::kSessionClose);
    TEST_CHECK(session_close != nullptr && session_close->result == relay::trace_result::kOk,
               "session_close trace mismatch for " + std::string(inbound_type));
    const auto close_reason_it = session_close->extra.find("close_reason");
    TEST_CHECK(close_reason_it != session_close->extra.end() && close_reason_it->second == "idle_timeout",
               "unexpected close_reason for " + std::string(inbound_type));

    TEST_CHECK(find_event(snapshot, relay::trace_stage::kSessionError) == nullptr,
               "unexpected session_error event for " + std::string(inbound_type));
    return std::nullopt;
}

[[nodiscard]] test_result expect_stopped_trace(const relay::trace_session_snapshot& snapshot, std::string_view inbound_type)
{
    const auto& summary = snapshot.summary;
    TEST_CHECK(summary.status == relay::trace_status::kStopped, "unexpected trace status for " + std::string(inbound_type));
    TEST_CHECK(summary.inbound_type == inbound_type, "unexpected inbound_type for " + std::string(inbound_type) + ": " + summary.inbound_type);
    TEST_CHECK(summary.route_type == "direct", "unexpected route_type for " + std::string(inbound_type) + ": " + summary.route_type);
    TEST_CHECK(summary.lifecycle.route_decide_done, "route_decide_done missing for " + std::string(inbound_type));
    TEST_CHECK(summary.lifecycle.outbound_connect_done, "outbound_connect_done missing for " + std::string(inbound_type));

    const auto* session_error = find_event(snapshot, relay::trace_stage::kSessionError);
    const auto* session_close = find_event(snapshot, relay::trace_stage::kSessionClose);
    TEST_CHECK((session_error == nullptr) != (session_close == nullptr),
               "unexpected terminal trace count for " + std::string(inbound_type));

    const auto* terminal = session_error != nullptr ? session_error : session_close;
    const auto close_reason_it = terminal->extra.find("close_reason");
    TEST_CHECK(close_reason_it != terminal->extra.end() && close_reason_it->second == "stopped",
               "unexpected close_reason for " + std::string(inbound_type));

    for (const auto& event : snapshot.events)
    {
        const auto it = event.extra.find("close_reason");
        if (it != event.extra.end() && it->second == "transport_error")
        {
            return fail_test("transport_error leaked into stopped trace for " + std::string(inbound_type));
        }
    }

    TEST_CHECK((session_close != nullptr) == summary.lifecycle.session_close,
               "session_close lifecycle mismatch for " + std::string(inbound_type));
    TEST_CHECK((session_error != nullptr) == summary.lifecycle.session_error,
               "session_error lifecycle mismatch for " + std::string(inbound_type));
    return std::nullopt;
}

[[nodiscard]] test_result expect_proxy_connect_fail_trace(const relay::trace_session_snapshot& snapshot, std::string_view inbound_type)
{
    const auto& summary = snapshot.summary;
    TEST_CHECK(summary.status == relay::trace_status::kFailed, "unexpected trace status for " + std::string(inbound_type));
    TEST_CHECK(summary.inbound_type == inbound_type, "unexpected inbound_type for " + std::string(inbound_type) + ": " + summary.inbound_type);
    TEST_CHECK(summary.outbound_tag == "socks-out", "unexpected outbound_tag for " + std::string(inbound_type) + ": " + summary.outbound_tag);
    TEST_CHECK(summary.route_type == "proxy", "unexpected route_type for " + std::string(inbound_type) + ": " + summary.route_type);
    TEST_CHECK(summary.lifecycle.route_decide_done, "route_decide_done missing for " + std::string(inbound_type));
    TEST_CHECK(summary.lifecycle.outbound_connect_start && summary.lifecycle.outbound_connect_done,
               "outbound_connect lifecycle missing for " + std::string(inbound_type));
    TEST_CHECK(summary.lifecycle.session_error && !summary.lifecycle.session_close,
               "unexpected session terminal lifecycle for " + std::string(inbound_type));

    const auto* connect_done = find_event(snapshot, relay::trace_stage::kOutboundConnectDone);
    TEST_CHECK(connect_done != nullptr && connect_done->result == relay::trace_result::kFail && !connect_done->error_message.empty(),
               "unexpected outbound_connect_done for " + std::string(inbound_type));

    const auto* session_error = find_event(snapshot, relay::trace_stage::kSessionError);
    TEST_CHECK(session_error != nullptr && session_error->result == relay::trace_result::kFail,
               "unexpected session_error for " + std::string(inbound_type));
    const auto close_reason_it = session_error->extra.find("close_reason");
    TEST_CHECK(close_reason_it != session_error->extra.end() && close_reason_it->second == "transport_error",
               "unexpected close_reason for " + std::string(inbound_type));

    TEST_CHECK(find_event(snapshot, relay::trace_stage::kSessionClose) == nullptr,
               "unexpected session_close for " + std::string(inbound_type));
    return std::nullopt;
}

[[nodiscard]] test_result expect_transport_error_trace(const relay::trace_session_snapshot& snapshot, std::string_view inbound_type)
{
    const auto& summary = snapshot.summary;
    TEST_CHECK(summary.status == relay::trace_status::kFailed, "unexpected trace status for " + std::string(inbound_type));
    TEST_CHECK(summary.inbound_type == inbound_type, "unexpected inbound_type for " + std::string(inbound_type) + ": " + summary.inbound_type);
    TEST_CHECK(summary.outbound_tag == "socks-out", "unexpected outbound_tag for " + std::string(inbound_type) + ": " + summary.outbound_tag);
    TEST_CHECK(summary.route_type == "proxy", "unexpected route_type for " + std::string(inbound_type) + ": " + summary.route_type);
    TEST_CHECK(summary.lifecycle.outbound_connect_done, "outbound_connect_done missing for " + std::string(inbound_type));
    TEST_CHECK(summary.lifecycle.session_error && !summary.lifecycle.session_close,
               "unexpected session lifecycle for " + std::string(inbound_type));

    const auto* connect_done = find_event(snapshot, relay::trace_stage::kOutboundConnectDone);
    TEST_CHECK(connect_done != nullptr && connect_done->result == relay::trace_result::kOk,
               "unexpected outbound_connect_done result for " + std::string(inbound_type));

    const auto* session_error = find_event(snapshot, relay::trace_stage::kSessionError);
    TEST_CHECK(session_error != nullptr && session_error->result == relay::trace_result::kFail,
               "unexpected session_error for " + std::string(inbound_type));
    const auto close_reason_it = session_error->extra.find("close_reason");
    TEST_CHECK(close_reason_it != session_error->extra.end() && close_reason_it->second == "transport_error",
               "unexpected close_reason for " + std::string(inbound_type));

    TEST_CHECK(find_event(snapshot, relay::trace_stage::kSessionClose) == nullptr,
               "unexpected session_close for " + std::string(inbound_type));
    return std::nullopt;
}

[[nodiscard]] test_result expect_proxy_transport_error_trace(const relay::trace_session_snapshot& snapshot,
                                                             std::string_view inbound_type,
                                                             const std::string& expected_outbound_tag)
{
    const auto& summary = snapshot.summary;
    TEST_CHECK(summary.status == relay::trace_status::kFailed, "unexpected trace status for " + std::string(inbound_type));
    TEST_CHECK(summary.inbound_type == inbound_type, "unexpected inbound_type for " + std::string(inbound_type) + ": " + summary.inbound_type);
    TEST_CHECK(summary.outbound_tag == expected_outbound_tag,
               "unexpected outbound_tag for " + std::string(inbound_type) + ": " + summary.outbound_tag);
    TEST_CHECK(summary.route_type == "proxy", "unexpected route_type for " + std::string(inbound_type) + ": " + summary.route_type);
    TEST_CHECK(summary.lifecycle.route_decide_done && summary.lifecycle.outbound_connect_done,
               "proxy lifecycle missing for " + std::string(inbound_type));
    TEST_CHECK(summary.lifecycle.session_error && !summary.lifecycle.session_close,
               "unexpected terminal lifecycle for " + std::string(inbound_type));

    const auto* connect_done = find_event(snapshot, relay::trace_stage::kOutboundConnectDone);
    TEST_CHECK(connect_done != nullptr && connect_done->result == relay::trace_result::kOk &&
                   connect_done->outbound_tag == expected_outbound_tag,
               "unexpected outbound_connect_done for " + std::string(inbound_type));

    const auto* session_error = find_event(snapshot, relay::trace_stage::kSessionError);
    TEST_CHECK(session_error != nullptr, "session_error missing for " + std::string(inbound_type));
    const auto close_reason_it = session_error->extra.find("close_reason");
    TEST_CHECK(close_reason_it != session_error->extra.end() && close_reason_it->second == "transport_error",
               "unexpected close_reason for " + std::string(inbound_type));
    return std::nullopt;
}

[[nodiscard]] test_result expect_direct_connect_fail_trace(const relay::trace_session_snapshot& snapshot, std::string_view inbound_type)
{
    const auto& summary = snapshot.summary;
    TEST_CHECK(summary.status == relay::trace_status::kFailed, "unexpected trace status for " + std::string(inbound_type));
    TEST_CHECK(summary.inbound_type == inbound_type, "unexpected inbound_type for " + std::string(inbound_type) + ": " + summary.inbound_type);
    TEST_CHECK(summary.outbound_tag == "direct", "unexpected outbound_tag for " + std::string(inbound_type) + ": " + summary.outbound_tag);
    TEST_CHECK(summary.route_type == "direct", "unexpected route_type for " + std::string(inbound_type) + ": " + summary.route_type);
    TEST_CHECK(summary.lifecycle.outbound_connect_start && summary.lifecycle.outbound_connect_done,
               "outbound_connect lifecycle missing for " + std::string(inbound_type));
    TEST_CHECK(summary.lifecycle.session_error && !summary.lifecycle.session_close,
               "unexpected session lifecycle for " + std::string(inbound_type));

    const auto* connect_done = find_event(snapshot, relay::trace_stage::kOutboundConnectDone);
    TEST_CHECK(connect_done != nullptr && connect_done->result == relay::trace_result::kFail && !connect_done->error_message.empty(),
               "unexpected outbound_connect_done for " + std::string(inbound_type));

    const auto* session_error = find_event(snapshot, relay::trace_stage::kSessionError);
    TEST_CHECK(session_error != nullptr && session_error->result == relay::trace_result::kFail,
               "unexpected session_error for " + std::string(inbound_type));
    const auto close_reason_it = session_error->extra.find("close_reason");
    TEST_CHECK(close_reason_it != session_error->extra.end() && close_reason_it->second == "transport_error",
               "unexpected close_reason for " + std::string(inbound_type));

    TEST_CHECK(find_event(snapshot, relay::trace_stage::kSessionClose) == nullptr,
               "unexpected session_close for " + std::string(inbound_type));
    return std::nullopt;
}

[[nodiscard]] test_result wait_close(std::future<void>& closed_future, std::string_view label)
{
    TEST_CHECK(closed_future.wait_for(5s) == std::future_status::ready,
               "timeout waiting session close for " + std::string(label));
    closed_future.get();
    return std::nullopt;
}

void report_case_result(std::string_view scenario,
                        std::string_view inbound_type,
                        const test_result& result,
                        int& passed,
                        int& failed)
{
    if (!result.has_value())
    {
        ++passed;
        std::cout << "PASS " << scenario << ' ' << inbound_type << '\n';
        return;
    }

    ++failed;
    std::cerr << "FAIL " << scenario << ' ' << inbound_type << ": " << *result << '\n';
}

[[nodiscard]] test_result summarize_case_group(std::string_view scenario, const int passed, const int failed)
{
    std::cout << "summary: passed=" << passed << " failed=" << failed << " total=" << (passed + failed) << '\n';
    if (failed != 0)
    {
        return fail_test(std::string(scenario) + " regression failed");
    }
    return std::nullopt;
}

[[nodiscard]] test_result run_tproxy_route_blocked_case()
{
    io_worker_runtime runtime;
    auto cfg = make_route_blocked_config();
    std::shared_ptr<relay::router> route;
    TEST_RETURN_IF_ERROR(build_router(cfg, "tproxy-in", route));

    std::promise<void> closed_promise;
    auto closed_future = closed_promise.get_future();
    auto session = std::make_shared<relay::tproxy_udp_session>(runtime.worker(),
                                                               route,
                                                               boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 40001),
                                                               boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 53001),
                                                               1,
                                                               "tproxy-in",
                                                               cfg,
                                                               [&closed_promise]() { closed_promise.set_value(); });
    session->start();

    TEST_RETURN_IF_ERROR(wait_close(closed_future, "tproxy route_blocked"));
    TEST_RETURN_IF_ERROR(runtime.wait_until_idle());

    relay::trace_session_snapshot snapshot;
    TEST_RETURN_IF_ERROR(require_single_trace("tproxy-in", snapshot));
    TEST_RETURN_IF_ERROR(expect_route_blocked_trace(snapshot, "tproxy"));
    return std::nullopt;
}

[[nodiscard]] test_result run_tun_route_blocked_case()
{
    io_worker_runtime runtime;
    auto cfg = make_route_blocked_config();
    std::shared_ptr<relay::router> route;
    TEST_RETURN_IF_ERROR(build_router(cfg, "tun-in", route));

    lwip_udp_pcb_holder pcb_holder;
    TEST_CHECK(pcb_holder.valid(), "udp_new_ip_type failed");
    std::promise<void> closed_promise;
    auto closed_future = closed_promise.get_future();
    auto session = std::make_shared<relay::tun_udp_session>(runtime.worker(),
                                                            route,
                                                            pcb_holder.release(),
                                                            boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 40002),
                                                            boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 53002),
                                                            2,
                                                            "tun-in",
                                                            cfg,
                                                            [&closed_promise]() { closed_promise.set_value(); });
    runtime.worker().group.spawn([session]() { return session->start(); });

    TEST_RETURN_IF_ERROR(wait_close(closed_future, "tun route_blocked"));
    TEST_RETURN_IF_ERROR(runtime.wait_until_idle());

    relay::trace_session_snapshot snapshot;
    TEST_RETURN_IF_ERROR(require_single_trace("tun-in", snapshot));
    TEST_RETURN_IF_ERROR(expect_route_blocked_trace(snapshot, "tun"));
    return std::nullopt;
}

[[nodiscard]] test_result run_tproxy_idle_timeout_case()
{
    io_worker_runtime runtime;
    const auto cfg = make_direct_config(1);
    std::shared_ptr<relay::router> route;
    TEST_RETURN_IF_ERROR(build_router(cfg, "tproxy-in", route));

    udp_blackhole_server blackhole;
    const auto client_endpoint = boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 41001);
    const auto target_endpoint = blackhole.endpoint();

    for (uint32_t conn_id = 101; conn_id <= 102; ++conn_id)
    {
        std::promise<void> closed_promise;
        auto closed_future = closed_promise.get_future();
        auto session = std::make_shared<relay::tproxy_udp_session>(runtime.worker(),
                                                                   route,
                                                                   client_endpoint,
                                                                   target_endpoint,
                                                                   conn_id,
                                                                   "tproxy-in",
                                                                   cfg,
                                                                   [&closed_promise]() { closed_promise.set_value(); });
        session->start();

        TEST_RETURN_IF_ERROR(expect_enqueue_result(runtime.worker().io_context,
                                                   session->enqueue_packet(std::vector<uint8_t>{'i', 'd', 'l', 'e'}),
                                                   relay::udp_enqueue_result::kEnqueued,
                                                   "enqueue tproxy idle packet failed"));

        TEST_RETURN_IF_ERROR(wait_close(closed_future, "tproxy idle_timeout"));
        TEST_RETURN_IF_ERROR(runtime.wait_until_idle());

        relay::trace_session_snapshot snapshot;
        TEST_RETURN_IF_ERROR(require_trace_by_conn_id("tproxy-in", conn_id, snapshot));
        TEST_RETURN_IF_ERROR(expect_idle_timeout_trace(snapshot, "tproxy"));
    }
    return std::nullopt;
}

[[nodiscard]] test_result make_udp_pbuf(const std::string_view payload, pbuf*& packet)
{
    packet = pbuf_alloc(PBUF_TRANSPORT, static_cast<u16_t>(payload.size()), PBUF_RAM);
    TEST_CHECK(packet != nullptr, "pbuf_alloc failed");
    if (pbuf_take(packet, payload.data(), static_cast<u16_t>(payload.size())) != ERR_OK)
    {
        pbuf_free(packet);
        packet = nullptr;
        return fail_test("pbuf_take failed");
    }
    return std::nullopt;
}

[[nodiscard]] test_result run_tun_idle_timeout_case()
{
    io_worker_runtime runtime;
    const auto cfg = make_direct_config(1);
    std::shared_ptr<relay::router> route;
    TEST_RETURN_IF_ERROR(build_router(cfg, "tun-in", route));

    udp_blackhole_server blackhole;
    const auto client_endpoint = boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 41002);
    const auto target_endpoint = blackhole.endpoint();

    for (uint32_t conn_id = 201; conn_id <= 202; ++conn_id)
    {
        lwip_udp_pcb_holder pcb_holder;
        TEST_CHECK(pcb_holder.valid(), "udp_new_ip_type failed");
        std::promise<void> closed_promise;
        auto closed_future = closed_promise.get_future();
        auto session = std::make_shared<relay::tun_udp_session>(runtime.worker(),
                                                                route,
                                                                pcb_holder.release(),
                                                                client_endpoint,
                                                                target_endpoint,
                                                                conn_id,
                                                                "tun-in",
                                                                cfg,
                                                                [&closed_promise]() { closed_promise.set_value(); });
        runtime.worker().group.spawn([session]() { return session->start(); });
        pbuf* packet = nullptr;
        TEST_RETURN_IF_ERROR(make_udp_pbuf("idle", packet));
        session->enqueue_packet(packet);

        TEST_RETURN_IF_ERROR(wait_close(closed_future, "tun idle_timeout"));
        TEST_RETURN_IF_ERROR(runtime.wait_until_idle());

        relay::trace_session_snapshot snapshot;
        TEST_RETURN_IF_ERROR(require_trace_by_conn_id("tun-in", conn_id, snapshot));
        TEST_RETURN_IF_ERROR(expect_idle_timeout_trace(snapshot, "tun"));
    }
    return std::nullopt;
}

[[nodiscard]] test_result run_idle_timeout()
{
    int passed = 0;
    int failed = 0;

    report_case_result("idle_timeout", "tproxy", run_tproxy_idle_timeout_case(), passed, failed);
    report_case_result("idle_timeout", "tun", run_tun_idle_timeout_case(), passed, failed);
    return summarize_case_group("idle_timeout", passed, failed);
}

[[nodiscard]] test_result run_tproxy_concurrent_sessions_case()
{
    io_worker_runtime runtime;
    const auto cfg = make_direct_config(1);
    std::shared_ptr<relay::router> route;
    TEST_RETURN_IF_ERROR(build_router(cfg, "tproxy-in", route));

    udp_blackhole_server blackhole;
    const auto target_endpoint = blackhole.endpoint();
    const std::array<uint16_t, 3> client_ports{{43101, 43102, 43103}};
    const std::array<uint32_t, 3> conn_ids{{701, 702, 703}};
    std::vector<std::future<void>> closed_futures;
    std::vector<std::shared_ptr<std::promise<void>>> close_promises;
    std::vector<std::shared_ptr<relay::tproxy_udp_session>> sessions;
    closed_futures.reserve(client_ports.size());
    close_promises.reserve(client_ports.size());
    sessions.reserve(client_ports.size());

    for (std::size_t i = 0; i < client_ports.size(); ++i)
    {
        auto close_promise = std::make_shared<std::promise<void>>();
        closed_futures.push_back(close_promise->get_future());
        close_promises.push_back(close_promise);

        auto session = std::make_shared<relay::tproxy_udp_session>(runtime.worker(),
                                                                   route,
                                                                   boost::asio::ip::udp::endpoint(
                                                                       boost::asio::ip::make_address("127.0.0.1"), client_ports[i]),
                                                                   target_endpoint,
                                                                   conn_ids[i],
                                                                   "tproxy-in",
                                                                   cfg,
                                                                   [close_promise]() { close_promise->set_value(); });
        session->start();
        sessions.push_back(std::move(session));
    }

    for (auto& session : sessions)
    {
        TEST_RETURN_IF_ERROR(expect_enqueue_result(runtime.worker().io_context,
                                                   session->enqueue_packet(std::vector<uint8_t>{'c', 'o', 'n', 'c'}),
                                                   relay::udp_enqueue_result::kEnqueued,
                                                   "enqueue tproxy concurrent packet failed"));
    }

    for (std::size_t i = 0; i < closed_futures.size(); ++i)
    {
        TEST_RETURN_IF_ERROR(wait_close(closed_futures[i], "tproxy concurrent conn " + std::to_string(conn_ids[i])));
    }
    TEST_RETURN_IF_ERROR(runtime.wait_until_idle());

    for (const auto conn_id : conn_ids)
    {
        relay::trace_session_snapshot snapshot;
        TEST_RETURN_IF_ERROR(require_trace_by_conn_id("tproxy-in", conn_id, snapshot));
        TEST_RETURN_IF_ERROR(expect_idle_timeout_trace(snapshot, "tproxy"));
    }
    return std::nullopt;
}

[[nodiscard]] test_result run_tun_concurrent_sessions_case()
{
    io_worker_runtime runtime;
    const auto cfg = make_direct_config(1);
    std::shared_ptr<relay::router> route;
    TEST_RETURN_IF_ERROR(build_router(cfg, "tun-in", route));

    udp_blackhole_server blackhole;
    const auto target_endpoint = blackhole.endpoint();
    const std::array<uint16_t, 3> client_ports{{43201, 43202, 43203}};
    const std::array<uint32_t, 3> conn_ids{{801, 802, 803}};
    std::vector<std::future<void>> closed_futures;
    std::vector<std::shared_ptr<std::promise<void>>> close_promises;
    std::vector<std::shared_ptr<relay::tun_udp_session>> sessions;
    std::vector<std::unique_ptr<lwip_udp_pcb_holder>> pcb_holders;
    closed_futures.reserve(client_ports.size());
    close_promises.reserve(client_ports.size());
    sessions.reserve(client_ports.size());
    pcb_holders.reserve(client_ports.size());

    for (std::size_t i = 0; i < client_ports.size(); ++i)
    {
        auto close_promise = std::make_shared<std::promise<void>>();
        closed_futures.push_back(close_promise->get_future());
        close_promises.push_back(close_promise);

        auto pcb_holder = std::make_unique<lwip_udp_pcb_holder>();
        TEST_CHECK(pcb_holder->valid(), "udp_new_ip_type failed");
        auto session = std::make_shared<relay::tun_udp_session>(runtime.worker(),
                                                                route,
                                                                pcb_holder->release(),
                                                                boost::asio::ip::udp::endpoint(
                                                                    boost::asio::ip::make_address("127.0.0.1"), client_ports[i]),
                                                                target_endpoint,
                                                                conn_ids[i],
                                                                "tun-in",
                                                                cfg,
                                                                [close_promise]() { close_promise->set_value(); });
        runtime.worker().group.spawn([session]() { return session->start(); });
        sessions.push_back(std::move(session));
        pcb_holders.push_back(std::move(pcb_holder));
    }

    for (auto& session : sessions)
    {
        pbuf* packet = nullptr;
        TEST_RETURN_IF_ERROR(make_udp_pbuf("conc", packet));
        session->enqueue_packet(packet);
    }

    for (std::size_t i = 0; i < closed_futures.size(); ++i)
    {
        TEST_RETURN_IF_ERROR(wait_close(closed_futures[i], "tun concurrent conn " + std::to_string(conn_ids[i])));
    }
    TEST_RETURN_IF_ERROR(runtime.wait_until_idle());

    for (const auto conn_id : conn_ids)
    {
        relay::trace_session_snapshot snapshot;
        TEST_RETURN_IF_ERROR(require_trace_by_conn_id("tun-in", conn_id, snapshot));
        TEST_RETURN_IF_ERROR(expect_idle_timeout_trace(snapshot, "tun"));
    }
    return std::nullopt;
}

[[nodiscard]] test_result run_concurrent_sessions()
{
    int passed = 0;
    int failed = 0;

    report_case_result("concurrent_sessions", "tproxy", run_tproxy_concurrent_sessions_case(), passed, failed);
    report_case_result("concurrent_sessions", "tun", run_tun_concurrent_sessions_case(), passed, failed);
    return summarize_case_group("concurrent_sessions", passed, failed);
}

[[nodiscard]] test_result run_tproxy_closed_no_io_case()
{
    io_worker_runtime runtime;
    const auto cfg = make_direct_config(30);
    std::shared_ptr<relay::router> route;
    TEST_RETURN_IF_ERROR(build_router(cfg, "tproxy-in", route));

    udp_blackhole_server blackhole;
    const auto client_endpoint = boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 43301);
    const auto target_endpoint = blackhole.endpoint();
    constexpr uint32_t conn_id = 901;

    std::promise<void> closed_promise;
    auto closed_future = closed_promise.get_future();
    auto session = std::make_shared<relay::tproxy_udp_session>(runtime.worker(),
                                                               route,
                                                               client_endpoint,
                                                               target_endpoint,
                                                               conn_id,
                                                               "tproxy-in",
                                                               cfg,
                                                               [&closed_promise]() { closed_promise.set_value(); });
    session->start();

    TEST_RETURN_IF_ERROR(expect_enqueue_result(runtime.worker().io_context,
                                               session->enqueue_packet(std::vector<uint8_t>{'c', 'l', 'o', 's'}),
                                               relay::udp_enqueue_result::kEnqueued,
                                               "enqueue tproxy close packet failed"));

    TEST_RETURN_IF_ERROR(wait_for_trace_stage("tproxy-in", conn_id, relay::trace_stage::kOutboundConnectDone, "tproxy closed_no_io"));
    session->stop();
    TEST_RETURN_IF_ERROR(wait_close(closed_future, "tproxy closed_no_io"));
    TEST_RETURN_IF_ERROR(runtime.wait_until_idle());

    relay::trace_session_snapshot before;
    TEST_RETURN_IF_ERROR(require_trace_by_conn_id("tproxy-in", conn_id, before));
    TEST_RETURN_IF_ERROR(expect_stopped_trace(before, "tproxy"));

    TEST_RETURN_IF_ERROR(expect_enqueue_result(runtime.worker().io_context,
                                               session->enqueue_packet(std::vector<uint8_t>{'l', 'a', 't', 'e'}),
                                               relay::udp_enqueue_result::kClosed,
                                               "late tproxy enqueue should be closed"));
    TEST_RETURN_IF_ERROR(runtime.wait_until_idle());

    relay::trace_session_snapshot after;
    TEST_RETURN_IF_ERROR(require_trace_by_conn_id("tproxy-in", conn_id, after));
    TEST_CHECK(after.events.size() == before.events.size(), "tproxy trace changed after close");
    TEST_RETURN_IF_ERROR(expect_stopped_trace(after, "tproxy"));
    return std::nullopt;
}

[[nodiscard]] test_result run_tun_closed_no_io_case()
{
    io_worker_runtime runtime;
    const auto cfg = make_direct_config(30);
    std::shared_ptr<relay::router> route;
    TEST_RETURN_IF_ERROR(build_router(cfg, "tun-in", route));

    udp_blackhole_server blackhole;
    const auto client_endpoint = boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 43302);
    const auto target_endpoint = blackhole.endpoint();
    constexpr uint32_t conn_id = 902;

    lwip_udp_pcb_holder pcb_holder;
    TEST_CHECK(pcb_holder.valid(), "udp_new_ip_type failed");
    std::promise<void> closed_promise;
    auto closed_future = closed_promise.get_future();
    auto session = std::make_shared<relay::tun_udp_session>(runtime.worker(),
                                                            route,
                                                            pcb_holder.release(),
                                                            client_endpoint,
                                                            target_endpoint,
                                                            conn_id,
                                                            "tun-in",
                                                            cfg,
                                                            [&closed_promise]() { closed_promise.set_value(); });
    runtime.worker().group.spawn([session]() { return session->start(); });
    pbuf* first_packet = nullptr;
    TEST_RETURN_IF_ERROR(make_udp_pbuf("clos", first_packet));
    session->enqueue_packet(first_packet);

    TEST_RETURN_IF_ERROR(wait_for_trace_stage("tun-in", conn_id, relay::trace_stage::kOutboundConnectDone, "tun closed_no_io"));
    session->stop();
    TEST_RETURN_IF_ERROR(wait_close(closed_future, "tun closed_no_io"));
    TEST_RETURN_IF_ERROR(runtime.wait_until_idle());

    relay::trace_session_snapshot before;
    TEST_RETURN_IF_ERROR(require_trace_by_conn_id("tun-in", conn_id, before));
    TEST_RETURN_IF_ERROR(expect_stopped_trace(before, "tun"));

    pbuf* late_packet = nullptr;
    TEST_RETURN_IF_ERROR(make_udp_pbuf("late", late_packet));
    session->enqueue_packet(late_packet);
    TEST_RETURN_IF_ERROR(runtime.wait_until_idle());

    relay::trace_session_snapshot after;
    TEST_RETURN_IF_ERROR(require_trace_by_conn_id("tun-in", conn_id, after));
    TEST_CHECK(after.events.size() == before.events.size(), "tun trace changed after close");
    TEST_RETURN_IF_ERROR(expect_stopped_trace(after, "tun"));
    return std::nullopt;
}

[[nodiscard]] test_result run_closed_no_io()
{
    int passed = 0;
    int failed = 0;

    report_case_result("closed_no_io", "tproxy", run_tproxy_closed_no_io_case(), passed, failed);
    report_case_result("closed_no_io", "tun", run_tun_closed_no_io_case(), passed, failed);
    return summarize_case_group("closed_no_io", passed, failed);
}

[[nodiscard]] test_result run_tproxy_direct_connect_fail_case()
{
    io_worker_runtime runtime;
    const auto cfg = make_direct_config(5);
    std::shared_ptr<relay::router> route;
    TEST_RETURN_IF_ERROR(build_router(cfg, "tproxy-in", route));

    std::promise<void> closed_promise;
    auto closed_future = closed_promise.get_future();
    auto session = std::make_shared<relay::tproxy_udp_session>(runtime.worker(),
                                                               route,
                                                               boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("::1"), 43401),
                                                               boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("fe80::1"), 53031),
                                                               951,
                                                               "tproxy-in",
                                                               cfg,
                                                               [&closed_promise]() { closed_promise.set_value(); });
    session->start();

    TEST_RETURN_IF_ERROR(wait_close(closed_future, "tproxy direct_connect_fail"));
    TEST_RETURN_IF_ERROR(runtime.wait_until_idle());

    relay::trace_session_snapshot snapshot;
    TEST_RETURN_IF_ERROR(require_trace_by_conn_id("tproxy-in", 951, snapshot));
    TEST_RETURN_IF_ERROR(expect_direct_connect_fail_trace(snapshot, "tproxy"));
    return std::nullopt;
}

[[nodiscard]] test_result run_tun_direct_connect_fail_case()
{
    io_worker_runtime runtime;
    const auto cfg = make_direct_config(5);
    std::shared_ptr<relay::router> route;
    TEST_RETURN_IF_ERROR(build_router(cfg, "tun-in", route));

    lwip_udp_pcb_holder pcb_holder;
    TEST_CHECK(pcb_holder.valid(), "udp_new_ip_type failed");
    std::promise<void> closed_promise;
    auto closed_future = closed_promise.get_future();
    auto session = std::make_shared<relay::tun_udp_session>(runtime.worker(),
                                                            route,
                                                            pcb_holder.release(),
                                                            boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("::1"), 43402),
                                                            boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("fe80::1"), 53032),
                                                            952,
                                                            "tun-in",
                                                            cfg,
                                                            [&closed_promise]() { closed_promise.set_value(); });
    runtime.worker().group.spawn([session]() { return session->start(); });

    TEST_RETURN_IF_ERROR(wait_close(closed_future, "tun direct_connect_fail"));
    TEST_RETURN_IF_ERROR(runtime.wait_until_idle());

    relay::trace_session_snapshot snapshot;
    TEST_RETURN_IF_ERROR(require_trace_by_conn_id("tun-in", 952, snapshot));
    TEST_RETURN_IF_ERROR(expect_direct_connect_fail_trace(snapshot, "tun"));
    return std::nullopt;
}

[[nodiscard]] test_result run_direct_connect_fail()
{
    int passed = 0;
    int failed = 0;

    report_case_result("direct_connect_fail", "tproxy", run_tproxy_direct_connect_fail_case(), passed, failed);
    report_case_result("direct_connect_fail", "tun", run_tun_direct_connect_fail_case(), passed, failed);
    return summarize_case_group("direct_connect_fail", passed, failed);
}

[[nodiscard]] test_result run_tproxy_stopped_case()
{
    io_worker_runtime runtime;
    const auto cfg = make_direct_config(30);
    std::shared_ptr<relay::router> route;
    TEST_RETURN_IF_ERROR(build_router(cfg, "tproxy-in", route));

    udp_blackhole_server blackhole;
    const auto client_endpoint = boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 42001);
    const auto target_endpoint = blackhole.endpoint();
    constexpr uint32_t conn_id = 301;

    std::promise<void> closed_promise;
    auto closed_future = closed_promise.get_future();
    auto session = std::make_shared<relay::tproxy_udp_session>(runtime.worker(),
                                                               route,
                                                               client_endpoint,
                                                               target_endpoint,
                                                               conn_id,
                                                               "tproxy-in",
                                                               cfg,
                                                               [&closed_promise]() { closed_promise.set_value(); });
    session->start();

    TEST_RETURN_IF_ERROR(expect_enqueue_result(runtime.worker().io_context,
                                               session->enqueue_packet(std::vector<uint8_t>{'s', 't', 'o', 'p'}),
                                               relay::udp_enqueue_result::kEnqueued,
                                               "enqueue tproxy stopped packet failed"));

    TEST_RETURN_IF_ERROR(wait_for_trace_stage("tproxy-in", conn_id, relay::trace_stage::kOutboundConnectDone, "tproxy stopped"));
    session->stop();

    TEST_RETURN_IF_ERROR(wait_close(closed_future, "tproxy stopped"));
    TEST_RETURN_IF_ERROR(runtime.wait_until_idle());

    relay::trace_session_snapshot snapshot;
    TEST_RETURN_IF_ERROR(require_trace_by_conn_id("tproxy-in", conn_id, snapshot));
    TEST_RETURN_IF_ERROR(expect_stopped_trace(snapshot, "tproxy"));
    return std::nullopt;
}

[[nodiscard]] test_result run_tun_stopped_case()
{
    io_worker_runtime runtime;
    const auto cfg = make_direct_config(30);
    std::shared_ptr<relay::router> route;
    TEST_RETURN_IF_ERROR(build_router(cfg, "tun-in", route));

    udp_blackhole_server blackhole;
    const auto client_endpoint = boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 42002);
    const auto target_endpoint = blackhole.endpoint();
    constexpr uint32_t conn_id = 401;

    lwip_udp_pcb_holder pcb_holder;
    TEST_CHECK(pcb_holder.valid(), "udp_new_ip_type failed");
    std::promise<void> closed_promise;
    auto closed_future = closed_promise.get_future();
    auto session = std::make_shared<relay::tun_udp_session>(runtime.worker(),
                                                            route,
                                                            pcb_holder.release(),
                                                            client_endpoint,
                                                            target_endpoint,
                                                            conn_id,
                                                            "tun-in",
                                                            cfg,
                                                            [&closed_promise]() { closed_promise.set_value(); });
    runtime.worker().group.spawn([session]() { return session->start(); });
    pbuf* packet = nullptr;
    TEST_RETURN_IF_ERROR(make_udp_pbuf("stop", packet));
    session->enqueue_packet(packet);

    TEST_RETURN_IF_ERROR(wait_for_trace_stage("tun-in", conn_id, relay::trace_stage::kOutboundConnectDone, "tun stopped"));
    session->stop();

    TEST_RETURN_IF_ERROR(wait_close(closed_future, "tun stopped"));
    TEST_RETURN_IF_ERROR(runtime.wait_until_idle());

    relay::trace_session_snapshot snapshot;
    TEST_RETURN_IF_ERROR(require_trace_by_conn_id("tun-in", conn_id, snapshot));
    TEST_RETURN_IF_ERROR(expect_stopped_trace(snapshot, "tun"));
    return std::nullopt;
}

[[nodiscard]] test_result run_stopped()
{
    int passed = 0;
    int failed = 0;

    report_case_result("stopped", "tproxy", run_tproxy_stopped_case(), passed, failed);
    report_case_result("stopped", "tun", run_tun_stopped_case(), passed, failed);
    return summarize_case_group("stopped", passed, failed);
}

uint16_t pick_unused_tcp_port()
{
    boost::asio::io_context io_context;
    boost::asio::ip::tcp::acceptor acceptor(io_context, {boost::asio::ip::make_address("127.0.0.1"), 0});
    return acceptor.local_endpoint().port();
}

[[nodiscard]] test_result run_tproxy_proxy_connect_fail_case()
{
    io_worker_runtime runtime;
    const auto cfg = make_proxy_fail_config(pick_unused_tcp_port());
    std::shared_ptr<relay::router> route;
    TEST_RETURN_IF_ERROR(build_router(cfg, "tproxy-in", route));

    std::promise<void> closed_promise;
    auto closed_future = closed_promise.get_future();
    auto session = std::make_shared<relay::tproxy_udp_session>(runtime.worker(),
                                                               route,
                                                               boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 43001),
                                                               boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 53011),
                                                               501,
                                                               "tproxy-in",
                                                               cfg,
                                                               [&closed_promise]() { closed_promise.set_value(); });
    session->start();

    TEST_RETURN_IF_ERROR(wait_close(closed_future, "tproxy proxy_connect_fail"));
    TEST_RETURN_IF_ERROR(runtime.wait_until_idle());

    relay::trace_session_snapshot snapshot;
    TEST_RETURN_IF_ERROR(require_trace_by_conn_id("tproxy-in", 501, snapshot));
    TEST_RETURN_IF_ERROR(expect_proxy_connect_fail_trace(snapshot, "tproxy"));
    return std::nullopt;
}

[[nodiscard]] test_result run_tun_proxy_connect_fail_case()
{
    io_worker_runtime runtime;
    const auto cfg = make_proxy_fail_config(pick_unused_tcp_port());
    std::shared_ptr<relay::router> route;
    TEST_RETURN_IF_ERROR(build_router(cfg, "tun-in", route));

    lwip_udp_pcb_holder pcb_holder;
    TEST_CHECK(pcb_holder.valid(), "udp_new_ip_type failed");
    std::promise<void> closed_promise;
    auto closed_future = closed_promise.get_future();
    auto session = std::make_shared<relay::tun_udp_session>(runtime.worker(),
                                                            route,
                                                            pcb_holder.release(),
                                                            boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 43002),
                                                            boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 53012),
                                                            502,
                                                            "tun-in",
                                                            cfg,
                                                            [&closed_promise]() { closed_promise.set_value(); });
    runtime.worker().group.spawn([session]() { return session->start(); });

    TEST_RETURN_IF_ERROR(wait_close(closed_future, "tun proxy_connect_fail"));
    TEST_RETURN_IF_ERROR(runtime.wait_until_idle());

    relay::trace_session_snapshot snapshot;
    TEST_RETURN_IF_ERROR(require_trace_by_conn_id("tun-in", 502, snapshot));
    TEST_RETURN_IF_ERROR(expect_proxy_connect_fail_trace(snapshot, "tun"));
    return std::nullopt;
}

[[nodiscard]] test_result run_proxy_connect_fail()
{
    int passed = 0;
    int failed = 0;

    report_case_result("proxy_connect_fail", "tproxy", run_tproxy_proxy_connect_fail_case(), passed, failed);
    report_case_result("proxy_connect_fail", "tun", run_tun_proxy_connect_fail_case(), passed, failed);
    return summarize_case_group("proxy_connect_fail", passed, failed);
}

[[nodiscard]] test_result run_tproxy_transport_error_case()
{
    io_worker_runtime runtime;
    fake_socks_udp_server server;
    const auto cfg = make_proxy_config(server.tcp_port());
    std::shared_ptr<relay::router> route;
    TEST_RETURN_IF_ERROR(build_router(cfg, "tproxy-in", route));

    std::promise<void> closed_promise;
    auto closed_future = closed_promise.get_future();
    auto session = std::make_shared<relay::tproxy_udp_session>(runtime.worker(),
                                                               route,
                                                               boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 44001),
                                                               boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 53021),
                                                               601,
                                                               "tproxy-in",
                                                               cfg,
                                                               [&closed_promise]() { closed_promise.set_value(); });
    session->start();

    TEST_RETURN_IF_ERROR(expect_enqueue_result(runtime.worker().io_context,
                                               session->enqueue_packet(std::vector<uint8_t>{'b', 'a', 'd'}),
                                               relay::udp_enqueue_result::kEnqueued,
                                               "enqueue tproxy transport packet failed"));

    TEST_RETURN_IF_ERROR(wait_close(closed_future, "tproxy transport_error"));
    TEST_RETURN_IF_ERROR(runtime.wait_until_idle());
    TEST_RETURN_IF_ERROR(server.join());

    relay::trace_session_snapshot snapshot;
    TEST_RETURN_IF_ERROR(require_trace_by_conn_id("tproxy-in", 601, snapshot));
    TEST_RETURN_IF_ERROR(expect_transport_error_trace(snapshot, "tproxy"));
    return std::nullopt;
}

[[nodiscard]] test_result run_tun_transport_error_case()
{
    io_worker_runtime runtime;
    fake_socks_udp_server server;
    const auto cfg = make_proxy_config(server.tcp_port());
    std::shared_ptr<relay::router> route;
    TEST_RETURN_IF_ERROR(build_router(cfg, "tun-in", route));

    lwip_udp_pcb_holder pcb_holder;
    TEST_CHECK(pcb_holder.valid(), "udp_new_ip_type failed");
    std::promise<void> closed_promise;
    auto closed_future = closed_promise.get_future();
    auto session = std::make_shared<relay::tun_udp_session>(runtime.worker(),
                                                            route,
                                                            pcb_holder.release(),
                                                            boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 44002),
                                                            boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 53022),
                                                            602,
                                                            "tun-in",
                                                            cfg,
                                                            [&closed_promise]() { closed_promise.set_value(); });
    runtime.worker().group.spawn([session]() { return session->start(); });
    pbuf* packet = nullptr;
    TEST_RETURN_IF_ERROR(make_udp_pbuf("bad", packet));
    session->enqueue_packet(packet);

    TEST_RETURN_IF_ERROR(wait_close(closed_future, "tun transport_error"));
    TEST_RETURN_IF_ERROR(runtime.wait_until_idle());
    TEST_RETURN_IF_ERROR(server.join());

    relay::trace_session_snapshot snapshot;
    TEST_RETURN_IF_ERROR(require_trace_by_conn_id("tun-in", 602, snapshot));
    TEST_RETURN_IF_ERROR(expect_transport_error_trace(snapshot, "tun"));
    return std::nullopt;
}

[[nodiscard]] test_result run_transport_error()
{
    int passed = 0;
    int failed = 0;

    report_case_result("transport_error", "tproxy", run_tproxy_transport_error_case(), passed, failed);
    report_case_result("transport_error", "tun", run_tun_transport_error_case(), passed, failed);
    return summarize_case_group("transport_error", passed, failed);
}

[[nodiscard]] test_result run_tproxy_multi_outbound_case()
{
    io_worker_runtime runtime;
    fake_socks_udp_server server(2);
    const auto cfg = make_multi_proxy_config(server.tcp_port(), server.tcp_port());
    std::shared_ptr<relay::router> route;
    TEST_RETURN_IF_ERROR(build_router(cfg, "tproxy-in", route));

    std::promise<void> first_closed_promise;
    std::promise<void> second_closed_promise;
    auto first_closed = first_closed_promise.get_future();
    auto second_closed = second_closed_promise.get_future();

    auto first = std::make_shared<relay::tproxy_udp_session>(runtime.worker(),
                                                             route,
                                                             boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 44101),
                                                             boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.2"), 53101),
                                                             1001,
                                                             "tproxy-in",
                                                             cfg,
                                                             [&first_closed_promise]() { first_closed_promise.set_value(); });
    auto second = std::make_shared<relay::tproxy_udp_session>(runtime.worker(),
                                                              route,
                                                              boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 44102),
                                                              boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.3"), 53102),
                                                              1002,
                                                              "tproxy-in",
                                                             cfg,
                                                             [&second_closed_promise]() { second_closed_promise.set_value(); });
    first->start();
    second->start();

    TEST_RETURN_IF_ERROR(expect_enqueue_result(runtime.worker().io_context,
                                               first->enqueue_packet(std::vector<uint8_t>{'o', 'n', 'e'}),
                                               relay::udp_enqueue_result::kEnqueued,
                                               "enqueue tproxy multi_outbound packet failed"));
    TEST_RETURN_IF_ERROR(expect_enqueue_result(runtime.worker().io_context,
                                               second->enqueue_packet(std::vector<uint8_t>{'t', 'w', 'o'}),
                                               relay::udp_enqueue_result::kEnqueued,
                                               "enqueue tproxy multi_outbound packet failed"));

    TEST_RETURN_IF_ERROR(wait_close(first_closed, "tproxy multi_outbound first"));
    TEST_RETURN_IF_ERROR(wait_close(second_closed, "tproxy multi_outbound second"));
    TEST_RETURN_IF_ERROR(runtime.wait_until_idle());
    TEST_RETURN_IF_ERROR(server.join());

    relay::trace_session_snapshot first_snapshot;
    relay::trace_session_snapshot second_snapshot;
    TEST_RETURN_IF_ERROR(require_trace_by_conn_id("tproxy-in", 1001, first_snapshot));
    TEST_RETURN_IF_ERROR(require_trace_by_conn_id("tproxy-in", 1002, second_snapshot));
    TEST_RETURN_IF_ERROR(expect_proxy_transport_error_trace(first_snapshot, "tproxy", "socks-out-a"));
    TEST_RETURN_IF_ERROR(expect_proxy_transport_error_trace(second_snapshot, "tproxy", "socks-out-b"));
    return std::nullopt;
}

[[nodiscard]] test_result run_tun_multi_outbound_case()
{
    io_worker_runtime runtime;
    fake_socks_udp_server server(2);
    const auto cfg = make_multi_proxy_config(server.tcp_port(), server.tcp_port());
    std::shared_ptr<relay::router> route;
    TEST_RETURN_IF_ERROR(build_router(cfg, "tun-in", route));

    lwip_udp_pcb_holder first_pcb;
    lwip_udp_pcb_holder second_pcb;
    TEST_CHECK(first_pcb.valid(), "udp_new_ip_type failed");
    TEST_CHECK(second_pcb.valid(), "udp_new_ip_type failed");
    std::promise<void> first_closed_promise;
    std::promise<void> second_closed_promise;
    auto first_closed = first_closed_promise.get_future();
    auto second_closed = second_closed_promise.get_future();

    auto first = std::make_shared<relay::tun_udp_session>(runtime.worker(),
                                                          route,
                                                          first_pcb.release(),
                                                          boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 44201),
                                                          boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.2"), 53201),
                                                          1101,
                                                          "tun-in",
                                                          cfg,
                                                          [&first_closed_promise]() { first_closed_promise.set_value(); });
    auto second = std::make_shared<relay::tun_udp_session>(runtime.worker(),
                                                           route,
                                                           second_pcb.release(),
                                                           boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 44202),
                                                           boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.3"), 53202),
                                                           1102,
                                                           "tun-in",
                                                           cfg,
                                                           [&second_closed_promise]() { second_closed_promise.set_value(); });
    runtime.worker().group.spawn([first]() { return first->start(); });
    runtime.worker().group.spawn([second]() { return second->start(); });
    pbuf* first_packet = nullptr;
    pbuf* second_packet = nullptr;
    TEST_RETURN_IF_ERROR(make_udp_pbuf("one", first_packet));
    TEST_RETURN_IF_ERROR(make_udp_pbuf("two", second_packet));
    first->enqueue_packet(first_packet);
    second->enqueue_packet(second_packet);

    TEST_RETURN_IF_ERROR(wait_close(first_closed, "tun multi_outbound first"));
    TEST_RETURN_IF_ERROR(wait_close(second_closed, "tun multi_outbound second"));
    TEST_RETURN_IF_ERROR(runtime.wait_until_idle());
    TEST_RETURN_IF_ERROR(server.join());

    relay::trace_session_snapshot first_snapshot;
    relay::trace_session_snapshot second_snapshot;
    TEST_RETURN_IF_ERROR(require_trace_by_conn_id("tun-in", 1101, first_snapshot));
    TEST_RETURN_IF_ERROR(require_trace_by_conn_id("tun-in", 1102, second_snapshot));
    TEST_RETURN_IF_ERROR(expect_proxy_transport_error_trace(first_snapshot, "tun", "socks-out-a"));
    TEST_RETURN_IF_ERROR(expect_proxy_transport_error_trace(second_snapshot, "tun", "socks-out-b"));
    return std::nullopt;
}

[[nodiscard]] test_result run_multi_outbound()
{
    int passed = 0;
    int failed = 0;

    report_case_result("multi_outbound", "tproxy", run_tproxy_multi_outbound_case(), passed, failed);
    report_case_result("multi_outbound", "tun", run_tun_multi_outbound_case(), passed, failed);
    return summarize_case_group("multi_outbound", passed, failed);
}

[[nodiscard]] test_result run_route_blocked()
{
    int passed = 0;
    int failed = 0;

    report_case_result("route_blocked", "tproxy", run_tproxy_route_blocked_case(), passed, failed);
    report_case_result("route_blocked", "tun", run_tun_route_blocked_case(), passed, failed);
    return summarize_case_group("route_blocked", passed, failed);
}

}    // namespace

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        std::cerr
            << "usage: udp_transparent_session_regression "
            << "<route_blocked|idle_timeout|concurrent_sessions|closed_no_io|stopped|proxy_connect_fail|direct_connect_fail|transport_error|"
            << "multi_outbound>\n";
        return 1;
    }

    lwip_init();

    const std::string scenario = argv[1];
    test_result result;
    if (scenario == "route_blocked")
    {
        result = run_route_blocked();
    }
    else if (scenario == "idle_timeout")
    {
        result = run_idle_timeout();
    }
    else if (scenario == "stopped")
    {
        result = run_stopped();
    }
    else if (scenario == "concurrent_sessions")
    {
        result = run_concurrent_sessions();
    }
    else if (scenario == "closed_no_io")
    {
        result = run_closed_no_io();
    }
    else if (scenario == "proxy_connect_fail")
    {
        result = run_proxy_connect_fail();
    }
    else if (scenario == "direct_connect_fail")
    {
        result = run_direct_connect_fail();
    }
    else if (scenario == "transport_error")
    {
        result = run_transport_error();
    }
    else if (scenario == "multi_outbound")
    {
        result = run_multi_outbound();
    }
    else
    {
        std::cerr << "unsupported scenario: " << scenario << '\n';
        return 1;
    }

    if (result.has_value())
    {
        std::cerr << *result << '\n';
        return 1;
    }
    return 0;
}
