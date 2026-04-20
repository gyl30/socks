#include <chrono>
#include <cstdint>
#include <exception>
#include <future>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/use_future.hpp>

#include "config.h"
#include "context_pool.h"
#include "router.h"
#include "tproxy_udp_session.h"
#include "trace_store.h"
#include "tun_lwip.h"
#include "tun_udp_session.h"

namespace
{

using namespace std::chrono_literals;

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

    void wait_until_idle()
    {
        auto future = boost::asio::co_spawn(worker_.io_context, worker_.group.async_wait(), boost::asio::use_future);
        const auto ec = future.get();
        if (ec)
        {
            throw std::runtime_error("wait task group failed: " + ec.message());
        }
    }

   private:
    relay::io_worker worker_;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work_guard_;
    std::thread thread_;
};

class lwip_udp_pcb_holder
{
   public:
    lwip_udp_pcb_holder() : pcb_(udp_new_ip_type(IPADDR_TYPE_ANY))
    {
        if (pcb_ == nullptr)
        {
            throw std::runtime_error("udp_new_ip_type failed");
        }
    }

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

relay::trace_session_snapshot require_single_trace(const std::string& inbound_tag)
{
    relay::trace_query query;
    query.inbound_tag = inbound_tag;
    query.limit = 10;

    const auto items = relay::trace_store::instance().list_traces(query);
    if (items.size() != 1)
    {
        throw std::runtime_error("unexpected trace count for " + inbound_tag + ": " + std::to_string(items.size()));
    }

    const auto snapshot = relay::trace_store::instance().get_trace(items.front().trace_id);
    if (!snapshot.has_value())
    {
        throw std::runtime_error("trace snapshot missing for " + inbound_tag);
    }
    return *snapshot;
}

relay::trace_session_snapshot require_trace_by_conn_id(const std::string& inbound_tag, const uint32_t conn_id)
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
        const auto snapshot = relay::trace_store::instance().get_trace(item.trace_id);
        if (!snapshot.has_value())
        {
            throw std::runtime_error("trace snapshot missing for " + inbound_tag + " conn " + std::to_string(conn_id));
        }
        return *snapshot;
    }

    throw std::runtime_error("trace not found for " + inbound_tag + " conn " + std::to_string(conn_id));
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

void wait_for_trace_stage(const std::string& inbound_tag,
                          const uint32_t conn_id,
                          const relay::trace_stage stage,
                          std::string_view label)
{
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (std::chrono::steady_clock::now() < deadline)
    {
        try
        {
            const auto snapshot = require_trace_by_conn_id(inbound_tag, conn_id);
            if (find_event(snapshot, stage) != nullptr)
            {
                return;
            }
        }
        catch (const std::exception&)
        {
        }
        std::this_thread::sleep_for(20ms);
    }

    throw std::runtime_error("timeout waiting trace stage for " + std::string(label));
}

void expect_route_blocked_trace(const relay::trace_session_snapshot& snapshot, std::string_view inbound_type)
{
    const auto& summary = snapshot.summary;
    if (summary.status != relay::trace_status::kFailed)
    {
        throw std::runtime_error("unexpected trace status for " + std::string(inbound_type));
    }
    if (summary.inbound_type != inbound_type)
    {
        throw std::runtime_error("unexpected inbound_type for " + std::string(inbound_type) + ": " + summary.inbound_type);
    }
    if (summary.route_type != "block")
    {
        throw std::runtime_error("unexpected route_type for " + std::string(inbound_type) + ": " + summary.route_type);
    }
    if (!summary.lifecycle.route_decide_done)
    {
        throw std::runtime_error("route_decide_done missing for " + std::string(inbound_type));
    }
    if (!summary.lifecycle.session_error)
    {
        throw std::runtime_error("session_error missing for " + std::string(inbound_type));
    }
    if (summary.lifecycle.session_close)
    {
        throw std::runtime_error("unexpected session_close for " + std::string(inbound_type));
    }

    const auto* route_done = find_event(snapshot, relay::trace_stage::kRouteDecideDone);
    if (route_done == nullptr || route_done->result != relay::trace_result::kFail)
    {
        throw std::runtime_error("route_decide_done trace mismatch for " + std::string(inbound_type));
    }

    const auto* session_error = find_event(snapshot, relay::trace_stage::kSessionError);
    if (session_error == nullptr)
    {
        throw std::runtime_error("session_error event missing for " + std::string(inbound_type));
    }
    const auto close_reason_it = session_error->extra.find("close_reason");
    if (close_reason_it == session_error->extra.end() || close_reason_it->second != "route_blocked")
    {
        throw std::runtime_error("unexpected close_reason for " + std::string(inbound_type));
    }
    if (session_error->error_message != "route blocked")
    {
        throw std::runtime_error("unexpected error_message for " + std::string(inbound_type) + ": " + session_error->error_message);
    }

    if (find_event(snapshot, relay::trace_stage::kSessionClose) != nullptr)
    {
        throw std::runtime_error("unexpected session_close event for " + std::string(inbound_type));
    }
}

void expect_idle_timeout_trace(const relay::trace_session_snapshot& snapshot, std::string_view inbound_type)
{
    const auto& summary = snapshot.summary;
    if (summary.status != relay::trace_status::kSuccess)
    {
        throw std::runtime_error("unexpected trace status for " + std::string(inbound_type));
    }
    if (summary.inbound_type != inbound_type)
    {
        throw std::runtime_error("unexpected inbound_type for " + std::string(inbound_type) + ": " + summary.inbound_type);
    }
    if (summary.route_type != "direct")
    {
        throw std::runtime_error("unexpected route_type for " + std::string(inbound_type) + ": " + summary.route_type);
    }
    if (!summary.lifecycle.route_decide_done)
    {
        throw std::runtime_error("route_decide_done missing for " + std::string(inbound_type));
    }
    if (!summary.lifecycle.outbound_connect_done)
    {
        throw std::runtime_error("outbound_connect_done missing for " + std::string(inbound_type));
    }
    if (!summary.lifecycle.session_close)
    {
        throw std::runtime_error("session_close missing for " + std::string(inbound_type));
    }
    if (summary.lifecycle.session_error)
    {
        throw std::runtime_error("unexpected session_error for " + std::string(inbound_type));
    }

    const auto* session_close = find_event(snapshot, relay::trace_stage::kSessionClose);
    if (session_close == nullptr || session_close->result != relay::trace_result::kOk)
    {
        throw std::runtime_error("session_close trace mismatch for " + std::string(inbound_type));
    }
    const auto close_reason_it = session_close->extra.find("close_reason");
    if (close_reason_it == session_close->extra.end() || close_reason_it->second != "idle_timeout")
    {
        throw std::runtime_error("unexpected close_reason for " + std::string(inbound_type));
    }

    if (find_event(snapshot, relay::trace_stage::kSessionError) != nullptr)
    {
        throw std::runtime_error("unexpected session_error event for " + std::string(inbound_type));
    }
}

void expect_stopped_trace(const relay::trace_session_snapshot& snapshot, std::string_view inbound_type)
{
    const auto& summary = snapshot.summary;
    if (summary.inbound_type != inbound_type)
    {
        throw std::runtime_error("unexpected inbound_type for " + std::string(inbound_type) + ": " + summary.inbound_type);
    }
    if (summary.route_type != "direct")
    {
        throw std::runtime_error("unexpected route_type for " + std::string(inbound_type) + ": " + summary.route_type);
    }
    if (!summary.lifecycle.route_decide_done)
    {
        throw std::runtime_error("route_decide_done missing for " + std::string(inbound_type));
    }
    if (!summary.lifecycle.outbound_connect_done)
    {
        throw std::runtime_error("outbound_connect_done missing for " + std::string(inbound_type));
    }

    const auto* session_error = find_event(snapshot, relay::trace_stage::kSessionError);
    const auto* session_close = find_event(snapshot, relay::trace_stage::kSessionClose);
    if ((session_error == nullptr) == (session_close == nullptr))
    {
        throw std::runtime_error("unexpected terminal trace count for " + std::string(inbound_type));
    }

    const auto* terminal = session_error != nullptr ? session_error : session_close;
    const auto close_reason_it = terminal->extra.find("close_reason");
    if (close_reason_it == terminal->extra.end() || close_reason_it->second != "stopped")
    {
        throw std::runtime_error("unexpected close_reason for " + std::string(inbound_type));
    }

    for (const auto& event : snapshot.events)
    {
        const auto it = event.extra.find("close_reason");
        if (it != event.extra.end() && it->second == "transport_error")
        {
            throw std::runtime_error("transport_error leaked into stopped trace for " + std::string(inbound_type));
        }
    }

    if (session_close != nullptr)
    {
        if (summary.status != relay::trace_status::kSuccess)
        {
            throw std::runtime_error("unexpected success status for " + std::string(inbound_type));
        }
        if (!summary.lifecycle.session_close || summary.lifecycle.session_error)
        {
            throw std::runtime_error("unexpected lifecycle for stopped session_close " + std::string(inbound_type));
        }
        return;
    }

    if (summary.status != relay::trace_status::kFailed)
    {
        throw std::runtime_error("unexpected failed status for " + std::string(inbound_type));
    }
    if (!summary.lifecycle.session_error || summary.lifecycle.session_close)
    {
        throw std::runtime_error("unexpected lifecycle for stopped session_error " + std::string(inbound_type));
    }
}

void wait_close(std::future<void>& closed_future, std::string_view label)
{
    if (closed_future.wait_for(5s) != std::future_status::ready)
    {
        throw std::runtime_error("timeout waiting session close for " + std::string(label));
    }
    closed_future.get();
}

void run_tproxy_route_blocked_case()
{
    io_worker_runtime runtime;
    auto cfg = make_route_blocked_config();
    auto route = std::make_shared<relay::router>(cfg, "tproxy-in");
    if (!route->load())
    {
        throw std::runtime_error("load tproxy router failed");
    }

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

    wait_close(closed_future, "tproxy route_blocked");
    runtime.wait_until_idle();

    const auto snapshot = require_single_trace("tproxy-in");
    expect_route_blocked_trace(snapshot, "tproxy");
}

void run_tun_route_blocked_case()
{
    io_worker_runtime runtime;
    auto cfg = make_route_blocked_config();
    auto route = std::make_shared<relay::router>(cfg, "tun-in");
    if (!route->load())
    {
        throw std::runtime_error("load tun router failed");
    }

    lwip_udp_pcb_holder pcb_holder;
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

    wait_close(closed_future, "tun route_blocked");
    runtime.wait_until_idle();

    const auto snapshot = require_single_trace("tun-in");
    expect_route_blocked_trace(snapshot, "tun");
}

void run_tproxy_idle_timeout_case()
{
    io_worker_runtime runtime;
    const auto cfg = make_direct_config(1);
    auto route = std::make_shared<relay::router>(cfg, "tproxy-in");
    if (!route->load())
    {
        throw std::runtime_error("load tproxy router failed");
    }

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

        auto enqueue_future = boost::asio::co_spawn(
            runtime.worker().io_context, session->enqueue_packet(std::vector<uint8_t>{'i', 'd', 'l', 'e'}), boost::asio::use_future);
        const auto enqueue_result = enqueue_future.get();
        if (enqueue_result != relay::udp_enqueue_result::kEnqueued)
        {
            throw std::runtime_error("enqueue tproxy idle packet failed");
        }

        wait_close(closed_future, "tproxy idle_timeout");
        runtime.wait_until_idle();

        const auto snapshot = require_trace_by_conn_id("tproxy-in", conn_id);
        expect_idle_timeout_trace(snapshot, "tproxy");
    }
}

[[nodiscard]] pbuf* make_udp_pbuf(const std::string_view payload)
{
    auto* packet = pbuf_alloc(PBUF_TRANSPORT, static_cast<u16_t>(payload.size()), PBUF_RAM);
    if (packet == nullptr)
    {
        throw std::runtime_error("pbuf_alloc failed");
    }
    if (pbuf_take(packet, payload.data(), static_cast<u16_t>(payload.size())) != ERR_OK)
    {
        pbuf_free(packet);
        throw std::runtime_error("pbuf_take failed");
    }
    return packet;
}

void run_tun_idle_timeout_case()
{
    io_worker_runtime runtime;
    const auto cfg = make_direct_config(1);
    auto route = std::make_shared<relay::router>(cfg, "tun-in");
    if (!route->load())
    {
        throw std::runtime_error("load tun router failed");
    }

    udp_blackhole_server blackhole;
    const auto client_endpoint = boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 41002);
    const auto target_endpoint = blackhole.endpoint();

    for (uint32_t conn_id = 201; conn_id <= 202; ++conn_id)
    {
        lwip_udp_pcb_holder pcb_holder;
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
        session->enqueue_packet(make_udp_pbuf("idle"));

        wait_close(closed_future, "tun idle_timeout");
        runtime.wait_until_idle();

        const auto snapshot = require_trace_by_conn_id("tun-in", conn_id);
        expect_idle_timeout_trace(snapshot, "tun");
    }
}

void run_idle_timeout()
{
    int passed = 0;
    int failed = 0;

    try
    {
        run_tproxy_idle_timeout_case();
        ++passed;
        std::cout << "PASS idle_timeout tproxy\n";
    }
    catch (const std::exception& ex)
    {
        ++failed;
        std::cerr << "FAIL idle_timeout tproxy: " << ex.what() << '\n';
    }

    try
    {
        run_tun_idle_timeout_case();
        ++passed;
        std::cout << "PASS idle_timeout tun\n";
    }
    catch (const std::exception& ex)
    {
        ++failed;
        std::cerr << "FAIL idle_timeout tun: " << ex.what() << '\n';
    }

    std::cout << "summary: passed=" << passed << " failed=" << failed << " total=" << (passed + failed) << '\n';
    if (failed != 0)
    {
        throw std::runtime_error("idle_timeout regression failed");
    }
}

void run_tproxy_stopped_case()
{
    io_worker_runtime runtime;
    const auto cfg = make_direct_config(30);
    auto route = std::make_shared<relay::router>(cfg, "tproxy-in");
    if (!route->load())
    {
        throw std::runtime_error("load tproxy router failed");
    }

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

    auto enqueue_future = boost::asio::co_spawn(
        runtime.worker().io_context, session->enqueue_packet(std::vector<uint8_t>{'s', 't', 'o', 'p'}), boost::asio::use_future);
    const auto enqueue_result = enqueue_future.get();
    if (enqueue_result != relay::udp_enqueue_result::kEnqueued)
    {
        throw std::runtime_error("enqueue tproxy stopped packet failed");
    }

    wait_for_trace_stage("tproxy-in", conn_id, relay::trace_stage::kOutboundConnectDone, "tproxy stopped");
    session->stop();

    wait_close(closed_future, "tproxy stopped");
    runtime.wait_until_idle();

    const auto snapshot = require_trace_by_conn_id("tproxy-in", conn_id);
    expect_stopped_trace(snapshot, "tproxy");
}

void run_tun_stopped_case()
{
    io_worker_runtime runtime;
    const auto cfg = make_direct_config(30);
    auto route = std::make_shared<relay::router>(cfg, "tun-in");
    if (!route->load())
    {
        throw std::runtime_error("load tun router failed");
    }

    udp_blackhole_server blackhole;
    const auto client_endpoint = boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 42002);
    const auto target_endpoint = blackhole.endpoint();
    constexpr uint32_t conn_id = 401;

    lwip_udp_pcb_holder pcb_holder;
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
    session->enqueue_packet(make_udp_pbuf("stop"));

    wait_for_trace_stage("tun-in", conn_id, relay::trace_stage::kOutboundConnectDone, "tun stopped");
    session->stop();

    wait_close(closed_future, "tun stopped");
    runtime.wait_until_idle();

    const auto snapshot = require_trace_by_conn_id("tun-in", conn_id);
    expect_stopped_trace(snapshot, "tun");
}

void run_stopped()
{
    int passed = 0;
    int failed = 0;

    try
    {
        run_tproxy_stopped_case();
        ++passed;
        std::cout << "PASS stopped tproxy\n";
    }
    catch (const std::exception& ex)
    {
        ++failed;
        std::cerr << "FAIL stopped tproxy: " << ex.what() << '\n';
    }

    try
    {
        run_tun_stopped_case();
        ++passed;
        std::cout << "PASS stopped tun\n";
    }
    catch (const std::exception& ex)
    {
        ++failed;
        std::cerr << "FAIL stopped tun: " << ex.what() << '\n';
    }

    std::cout << "summary: passed=" << passed << " failed=" << failed << " total=" << (passed + failed) << '\n';
    if (failed != 0)
    {
        throw std::runtime_error("stopped regression failed");
    }
}

void run_route_blocked()
{
    int passed = 0;
    int failed = 0;

    try
    {
        run_tproxy_route_blocked_case();
        ++passed;
        std::cout << "PASS route_blocked tproxy\n";
    }
    catch (const std::exception& ex)
    {
        ++failed;
        std::cerr << "FAIL route_blocked tproxy: " << ex.what() << '\n';
    }

    try
    {
        run_tun_route_blocked_case();
        ++passed;
        std::cout << "PASS route_blocked tun\n";
    }
    catch (const std::exception& ex)
    {
        ++failed;
        std::cerr << "FAIL route_blocked tun: " << ex.what() << '\n';
    }

    std::cout << "summary: passed=" << passed << " failed=" << failed << " total=" << (passed + failed) << '\n';
    if (failed != 0)
    {
        throw std::runtime_error("route_blocked regression failed");
    }
}

}    // namespace

int main(int argc, char** argv)
{
    try
    {
        if (argc != 2)
        {
            throw std::runtime_error("usage: udp_transparent_session_regression <route_blocked|idle_timeout|stopped>");
        }

        lwip_init();

        const std::string scenario = argv[1];
        if (scenario == "route_blocked")
        {
            run_route_blocked();
            return 0;
        }
        if (scenario == "idle_timeout")
        {
            run_idle_timeout();
            return 0;
        }
        if (scenario == "stopped")
        {
            run_stopped();
            return 0;
        }

        throw std::runtime_error("unsupported scenario: " + scenario);
    }
    catch (const std::exception& ex)
    {
        std::cerr << ex.what() << '\n';
        return 1;
    }
}
