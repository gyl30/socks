#!/usr/bin/env python3

import argparse
import json
import socket
import struct
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional

from perf_baseline import (
    ProcessMonitor,
    UdpEchoServer,
    decode_udp_response,
    encode_udp_request,
    generate_key_pair,
    socks5_udp_associate,
    summarize_flow,
    terminate_process,
    write_json,
)


def average(values: List[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / float(len(values))


def average_optional(values: List[Optional[float]]) -> Optional[float]:
    present = [v for v in values if v is not None]
    if not present:
        return None
    return sum(present) / float(len(present))


def run_udp_burst_benchmark(
    proxy_host: str,
    proxy_port: int,
    target_host: str,
    target_port: int,
    iterations: int,
    payload_size: int,
    inflight: int,
    udp_timeout_ms: int,
    stall_timeout_sec: float,
) -> Dict[str, object]:
    if payload_size < 8:
        raise ValueError("payload_size must be >= 8")
    if inflight <= 0:
        raise ValueError("inflight must be > 0")

    ctrl, bind_host, bind_port = socks5_udp_associate(proxy_host, proxy_port)
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.settimeout(udp_timeout_ms / 1000.0)

    next_seq = 0
    success = 0
    pending: Dict[int, int] = {}
    rtts_ms: List[float] = []
    start = time.perf_counter()
    last_progress = start

    try:
        while True:
            while next_seq < iterations and len(pending) < inflight:
                body = struct.pack("!I", next_seq) + bytes([next_seq % 251]) * (payload_size - 4)
                req = encode_udp_request(target_host, target_port, body)
                udp_sock.sendto(req, (bind_host, bind_port))
                pending[next_seq] = time.perf_counter_ns()
                next_seq += 1

            if next_seq >= iterations and not pending:
                break

            try:
                raw, _ = udp_sock.recvfrom(65535)
            except socket.timeout:
                if (time.perf_counter() - last_progress) >= stall_timeout_sec:
                    break
                continue

            try:
                resp = decode_udp_response(raw)
            except RuntimeError:
                continue
            if len(resp) < 4:
                continue

            seq = struct.unpack("!I", resp[:4])[0]
            sent_ns = pending.pop(seq, None)
            if sent_ns is None:
                continue
            rtts_ms.append((time.perf_counter_ns() - sent_ns) / 1_000_000.0)
            success += 1
            last_progress = time.perf_counter()
    finally:
        try:
            udp_sock.close()
        except OSError:
            pass
        try:
            ctrl.close()
        except OSError:
            pass

    wall_sec = time.perf_counter() - start
    loss_rate = 1.0 - (success / float(iterations)) if iterations > 0 else 0.0
    total_bytes = success * payload_size
    summary = summarize_flow(rtts_ms, total_bytes, wall_sec, loss_rate)
    summary["success_count"] = success
    summary["sent_count"] = iterations
    summary["inflight"] = inflight
    return summary


def make_server_config(
    server_port: int,
    public_key: str,
    private_key: str,
    short_id: str,
    sni: str,
    queue_capacity: int,
) -> Dict[str, object]:
    return {
        "mode": "server",
        "log": {"level": "warn", "file": "perf_queue_server.log"},
        "inbound": {"host": "127.0.0.1", "port": server_port},
        "reality": {
            "sni": sni,
            "private_key": private_key,
            "public_key": public_key,
            "short_id": short_id,
        },
        "fallbacks": [],
        "timeout": {"idle": 120},
        "queues": {
            "udp_session_recv_channel_capacity": queue_capacity,
            "tproxy_udp_dispatch_queue_capacity": 2048,
        },
        "limits": {"max_connections": 20000},
    }


def make_client_config(
    server_port: int,
    socks_port: int,
    public_key: str,
    private_key: str,
    short_id: str,
    sni: str,
    queue_capacity: int,
) -> Dict[str, object]:
    return {
        "mode": "client",
        "log": {"level": "warn", "file": "perf_queue_client.log"},
        "inbound": {"host": "127.0.0.1", "port": socks_port},
        "outbound": {"host": "127.0.0.1", "port": server_port},
        "socks": {"host": "127.0.0.1", "port": socks_port, "auth": False},
        "reality": {
            "sni": sni,
            "public_key": public_key,
            "private_key": private_key,
            "short_id": short_id,
        },
        "timeout": {"idle": 120},
        "queues": {
            "udp_session_recv_channel_capacity": queue_capacity,
            "tproxy_udp_dispatch_queue_capacity": 2048,
        },
        "limits": {"max_connections": 20000},
    }


def run_capacity_once(
    build_dir: Path,
    socks_bin: str,
    queue_capacity: int,
    run_index: int,
    server_port: int,
    socks_port: int,
    udp_echo_port: int,
    iterations: int,
    payload_size: int,
    inflight: int,
    udp_timeout_ms: int,
    startup_wait_sec: float,
    stall_timeout_sec: float,
    public_key: str,
    private_key: str,
) -> Dict[str, object]:
    short_id = "0123456789abcdef"
    sni = "perf.queue.test"

    server_cfg_name = f"perf_queue_server_cap{queue_capacity}_run{run_index}.json"
    client_cfg_name = f"perf_queue_client_cap{queue_capacity}_run{run_index}.json"
    write_json(
        build_dir / server_cfg_name,
        make_server_config(server_port, public_key, private_key, short_id, sni, queue_capacity),
    )
    write_json(
        build_dir / client_cfg_name,
        make_client_config(server_port, socks_port, public_key, private_key, short_id, sni, queue_capacity),
    )

    server_proc: Optional[subprocess.Popen] = None
    client_proc: Optional[subprocess.Popen] = None

    try:
        server_proc = subprocess.Popen(
            [socks_bin, "-c", server_cfg_name],
            cwd=str(build_dir),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        client_proc = subprocess.Popen(
            [socks_bin, "-c", client_cfg_name],
            cwd=str(build_dir),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        time.sleep(startup_wait_sec)

        if server_proc.poll() is not None:
            raise RuntimeError(f"server exited unexpectedly for capacity={queue_capacity}")
        if client_proc.poll() is not None:
            raise RuntimeError(f"client exited unexpectedly for capacity={queue_capacity}")

        monitor = ProcessMonitor({server_proc.pid: "server", client_proc.pid: "client"})
        monitor.start()
        bench_start = time.perf_counter()
        udp_metrics = run_udp_burst_benchmark(
            proxy_host="127.0.0.1",
            proxy_port=socks_port,
            target_host="127.0.0.1",
            target_port=udp_echo_port,
            iterations=iterations,
            payload_size=payload_size,
            inflight=inflight,
            udp_timeout_ms=udp_timeout_ms,
            stall_timeout_sec=stall_timeout_sec,
        )
        bench_wall = time.perf_counter() - bench_start
        monitor.stop()

        return {
            "queue_capacity": queue_capacity,
            "run_index": run_index,
            "udp": udp_metrics,
            "process": monitor.summarize(bench_wall),
        }
    finally:
        terminate_process(client_proc)
        terminate_process(server_proc)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sweep UDP session recv channel capacity")
    parser.add_argument("--build-dir", default="build_release_perf")
    parser.add_argument("--socks-bin", default="./socks")
    parser.add_argument("--server-port", type=int, default=22060)
    parser.add_argument("--socks-port", type=int, default=12096)
    parser.add_argument("--udp-echo-port", type=int, default=19092)
    parser.add_argument("--iterations", type=int, default=12000)
    parser.add_argument("--payload-size", type=int, default=512)
    parser.add_argument("--inflight", type=int, default=256)
    parser.add_argument("--udp-timeout-ms", type=int, default=50)
    parser.add_argument("--stall-timeout-sec", type=float, default=1.5)
    parser.add_argument("--startup-wait-sec", type=float, default=2.0)
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--capacities", default="64,128,256,512,1024,2048")
    parser.add_argument("--out-json", default="build_release_perf/perf_queue_sweep_latest.json")
    return parser.parse_args()


def parse_capacities(text: str) -> List[int]:
    values: List[int] = []
    for part in text.split(","):
        token = part.strip()
        if not token:
            continue
        cap = int(token)
        if cap <= 0:
            raise ValueError("capacity must be > 0")
        if cap not in values:
            values.append(cap)
    if not values:
        raise ValueError("no capacities provided")
    return values


def aggregate_capacity_results(results: List[Dict[str, object]]) -> List[Dict[str, object]]:
    grouped: Dict[int, List[Dict[str, object]]] = {}
    for item in results:
        cap = int(item["queue_capacity"])
        grouped.setdefault(cap, []).append(item)

    summary: List[Dict[str, object]] = []
    for cap in sorted(grouped):
        runs = grouped[cap]
        throughput_values = [float(run["udp"]["throughput_mbps"]) for run in runs]
        loss_values = [float(run["udp"]["packet_loss_rate"]) for run in runs]
        p95_values = [run["udp"]["rtt_p95_ms"] for run in runs]
        p99_values = [run["udp"]["rtt_p99_ms"] for run in runs]
        rss_values = [float(run["process"]["peak_rss_mb_total"]) for run in runs]
        summary.append(
            {
                "queue_capacity": cap,
                "runs": len(runs),
                "throughput_mbps_avg": round(average(throughput_values), 3),
                "packet_loss_rate_avg": round(average(loss_values), 5),
                "rtt_p95_ms_avg": round(average_optional(p95_values), 3) if average_optional(p95_values) is not None else None,
                "rtt_p99_ms_avg": round(average_optional(p99_values), 3) if average_optional(p99_values) is not None else None,
                "peak_rss_mb_total_avg": round(average(rss_values), 3),
            }
        )
    return summary


def pick_recommended(summary: List[Dict[str, object]]) -> Dict[str, object]:
    def rank_key(item: Dict[str, object]) -> tuple:
        loss = float(item["packet_loss_rate_avg"])
        throughput = float(item["throughput_mbps_avg"])
        p95 = item["rtt_p95_ms_avg"]
        p95_value = float(p95) if p95 is not None else float("inf")
        capacity = int(item["queue_capacity"])
        return (loss, -throughput, p95_value, capacity)

    return min(summary, key=rank_key)


def main() -> int:
    args = parse_args()
    capacities = parse_capacities(args.capacities)
    build_dir = Path(args.build_dir)
    if not build_dir.exists():
        raise RuntimeError(f"build directory not found: {build_dir}")

    private_key, public_key = generate_key_pair(args.socks_bin, build_dir)
    udp_echo = UdpEchoServer("127.0.0.1", args.udp_echo_port)
    udp_echo.start()

    all_runs: List[Dict[str, object]] = []
    try:
        offset = 0
        for cap in capacities:
            for run_index in range(args.runs):
                server_port = args.server_port + offset
                socks_port = args.socks_port + offset
                print(
                    f"[queue-sweep] capacity={cap} run={run_index + 1}/{args.runs} "
                    f"server_port={server_port} socks_port={socks_port}",
                    flush=True,
                )
                result = run_capacity_once(
                    build_dir=build_dir,
                    socks_bin=args.socks_bin,
                    queue_capacity=cap,
                    run_index=run_index,
                    server_port=server_port,
                    socks_port=socks_port,
                    udp_echo_port=args.udp_echo_port,
                    iterations=args.iterations,
                    payload_size=args.payload_size,
                    inflight=args.inflight,
                    udp_timeout_ms=args.udp_timeout_ms,
                    startup_wait_sec=args.startup_wait_sec,
                    stall_timeout_sec=args.stall_timeout_sec,
                    public_key=public_key,
                    private_key=private_key,
                )
                all_runs.append(result)
                offset += 1
    finally:
        udp_echo.stop()

    summary = aggregate_capacity_results(all_runs)
    recommended = pick_recommended(summary)
    output = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "config": {
            "iterations": args.iterations,
            "payload_size_bytes": args.payload_size,
            "inflight": args.inflight,
            "udp_timeout_ms": args.udp_timeout_ms,
            "stall_timeout_sec": args.stall_timeout_sec,
            "runs_per_capacity": args.runs,
            "capacities": capacities,
        },
        "runs": all_runs,
        "summary": summary,
        "recommended": recommended,
    }

    out_path = Path(args.out_json)
    write_json(out_path, output)
    print(json.dumps(output, indent=2, ensure_ascii=False))
    print(f"[queue-sweep] wrote result to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
