#!/usr/bin/env python3

import argparse
import json
import os
import signal
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RuntimeError(f"socket closed while reading {n} bytes")
        buf.extend(chunk)
    return bytes(buf)


def percentile(values: List[float], p: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    idx = int(round((len(ordered) - 1) * p))
    return ordered[idx]


class TcpEchoServer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._running = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._sock.bind((self.host, self.port))
        self._sock.listen(128)
        self._running.set()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while self._running.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle_conn, args=(conn,), daemon=True).start()

    def _handle_conn(self, conn: socket.socket) -> None:
        try:
            while self._running.is_set():
                data = conn.recv(65535)
                if not data:
                    return
                conn.sendall(data)
        except OSError:
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self) -> None:
        self._running.clear()
        try:
            self._sock.close()
        except OSError:
            pass
        if self._thread is not None:
            self._thread.join(timeout=1)


class UdpEchoServer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._running = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._sock.bind((self.host, self.port))
        self._running.set()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while self._running.is_set():
            try:
                data, addr = self._sock.recvfrom(65535)
            except OSError:
                break
            try:
                self._sock.sendto(data, addr)
            except OSError:
                continue

    def stop(self) -> None:
        self._running.clear()
        try:
            self._sock.close()
        except OSError:
            pass
        if self._thread is not None:
            self._thread.join(timeout=1)


class ProcessMonitor:
    def __init__(self, pid_to_name: Dict[int, str]):
        self.pid_to_name = pid_to_name
        self._start_ticks: Dict[int, int] = {}
        self._end_ticks: Dict[int, int] = {}
        self._peak_rss_kb: Dict[int, int] = {}
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    @staticmethod
    def _read_cpu_ticks(pid: int) -> int:
        try:
            with open(f"/proc/{pid}/stat", "r", encoding="utf-8") as f:
                fields = f.read().strip().split()
            return int(fields[13]) + int(fields[14])
        except (FileNotFoundError, IndexError, ValueError):
            return 0

    @staticmethod
    def _read_rss_kb(pid: int) -> int:
        try:
            with open(f"/proc/{pid}/status", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        parts = line.split()
                        if len(parts) >= 2:
                            return int(parts[1])
        except (FileNotFoundError, ValueError):
            return 0
        return 0

    def start(self) -> None:
        for pid in self.pid_to_name:
            self._start_ticks[pid] = self._read_cpu_ticks(pid)
            self._peak_rss_kb[pid] = self._read_rss_kb(pid)
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            for pid in self.pid_to_name:
                rss = self._read_rss_kb(pid)
                if rss > self._peak_rss_kb.get(pid, 0):
                    self._peak_rss_kb[pid] = rss
            time.sleep(0.2)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1)
        for pid in self.pid_to_name:
            self._end_ticks[pid] = self._read_cpu_ticks(pid)

    def summarize(self, wall_sec: float) -> Dict[str, object]:
        ticks_per_sec = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
        per_proc = {}
        total_cpu_sec = 0.0
        total_peak_rss_kb = 0
        for pid, name in self.pid_to_name.items():
            start_ticks = self._start_ticks.get(pid, 0)
            end_ticks = self._end_ticks.get(pid, start_ticks)
            cpu_sec = max(0.0, (end_ticks - start_ticks) / float(ticks_per_sec))
            peak_rss_kb = self._peak_rss_kb.get(pid, 0)
            per_proc[name] = {
                "pid": pid,
                "cpu_time_sec": round(cpu_sec, 3),
                "peak_rss_mb": round(peak_rss_kb / 1024.0, 3),
            }
            total_cpu_sec += cpu_sec
            total_peak_rss_kb += peak_rss_kb
        cpu_util_percent = (total_cpu_sec / wall_sec * 100.0) if wall_sec > 0 else 0.0
        return {
            "wall_time_sec": round(wall_sec, 3),
            "cpu_time_sec_total": round(total_cpu_sec, 3),
            "cpu_util_percent_total": round(cpu_util_percent, 2),
            "peak_rss_mb_total": round(total_peak_rss_kb / 1024.0, 3),
            "processes": per_proc,
        }


def parse_socks5_bind(reply_head: bytes, sock: socket.socket) -> Tuple[str, int]:
    if len(reply_head) != 4:
        raise RuntimeError("invalid socks5 response header")
    ver, rep, _rsv, atyp = reply_head
    if ver != 0x05:
        raise RuntimeError(f"invalid socks version: {ver}")
    if rep != 0x00:
        raise RuntimeError(f"socks command rejected: rep={rep}")

    if atyp == 0x01:  # ipv4
        addr = socket.inet_ntoa(recv_exact(sock, 4))
    elif atyp == 0x03:  # domain
        ln = recv_exact(sock, 1)[0]
        addr = recv_exact(sock, ln).decode("utf-8", errors="ignore")
    elif atyp == 0x04:  # ipv6
        addr = socket.inet_ntop(socket.AF_INET6, recv_exact(sock, 16))
    else:
        raise RuntimeError(f"unknown atyp: {atyp}")
    port = struct.unpack("!H", recv_exact(sock, 2))[0]
    return addr, port


def socks5_handshake(sock: socket.socket) -> None:
    sock.sendall(b"\x05\x01\x00")
    resp = recv_exact(sock, 2)
    if resp != b"\x05\x00":
        raise RuntimeError(f"socks auth failed: {resp!r}")


def socks5_tcp_connect(proxy_host: str, proxy_port: int, target_host: str, target_port: int) -> socket.socket:
    sock = socket.create_connection((proxy_host, proxy_port), timeout=5)
    socks5_handshake(sock)
    req = b"\x05\x01\x00\x01" + socket.inet_aton(target_host) + struct.pack("!H", target_port)
    sock.sendall(req)
    parse_socks5_bind(recv_exact(sock, 4), sock)
    return sock


def socks5_udp_associate(proxy_host: str, proxy_port: int) -> Tuple[socket.socket, str, int]:
    ctrl = socket.create_connection((proxy_host, proxy_port), timeout=5)
    socks5_handshake(ctrl)
    req = b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00"
    ctrl.sendall(req)
    bind_host, bind_port = parse_socks5_bind(recv_exact(ctrl, 4), ctrl)
    return ctrl, bind_host, bind_port


def encode_udp_request(target_host: str, target_port: int, payload: bytes) -> bytes:
    return b"\x00\x00\x00\x01" + socket.inet_aton(target_host) + struct.pack("!H", target_port) + payload


def decode_udp_response(packet: bytes) -> bytes:
    if len(packet) < 10:
        raise RuntimeError("short udp response")
    if packet[2] != 0x00:
        raise RuntimeError("fragmented udp response not supported")
    atyp = packet[3]
    idx = 4
    if atyp == 0x01:
        idx += 4
    elif atyp == 0x03:
        if len(packet) < 5:
            raise RuntimeError("short domain udp response")
        idx += 1 + packet[4]
    elif atyp == 0x04:
        idx += 16
    else:
        raise RuntimeError(f"unknown udp atyp: {atyp}")
    if len(packet) < idx + 2:
        raise RuntimeError("short udp response without port")
    idx += 2
    return packet[idx:]


def summarize_flow(rtts_ms: List[float], total_bytes: int, wall_sec: float, loss_rate: float) -> Dict[str, object]:
    throughput_mbps = (total_bytes * 8.0 / wall_sec / 1_000_000.0) if wall_sec > 0 else 0.0
    return {
        "count": len(rtts_ms),
        "throughput_mbps": round(throughput_mbps, 3),
        "rtt_avg_ms": round(sum(rtts_ms) / len(rtts_ms), 3) if rtts_ms else None,
        "rtt_p50_ms": round(percentile(rtts_ms, 0.50), 3) if rtts_ms else None,
        "rtt_p95_ms": round(percentile(rtts_ms, 0.95), 3) if rtts_ms else None,
        "rtt_p99_ms": round(percentile(rtts_ms, 0.99), 3) if rtts_ms else None,
        "packet_loss_rate": round(loss_rate, 5),
        "wall_time_sec": round(wall_sec, 3),
    }


def run_tcp_benchmark(proxy_host: str, proxy_port: int, target_host: str, target_port: int, iterations: int, payload_size: int) -> Dict[str, object]:
    payload = bytes((i % 251 for i in range(payload_size)))
    sock = socks5_tcp_connect(proxy_host, proxy_port, target_host, target_port)
    sock.settimeout(3)
    rtts_ms: List[float] = []
    start = time.perf_counter()
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        sock.sendall(payload)
        echoed = recv_exact(sock, payload_size)
        if echoed != payload:
            raise RuntimeError("tcp echo payload mismatch")
        t1 = time.perf_counter_ns()
        rtts_ms.append((t1 - t0) / 1_000_000.0)
    wall_sec = time.perf_counter() - start
    try:
        sock.close()
    except OSError:
        pass
    total_bytes = iterations * payload_size
    return summarize_flow(rtts_ms, total_bytes, wall_sec, 0.0)


def run_udp_benchmark(
    proxy_host: str,
    proxy_port: int,
    target_host: str,
    target_port: int,
    iterations: int,
    payload_size: int,
    udp_timeout_ms: int,
) -> Dict[str, object]:
    if payload_size < 8:
        raise ValueError("udp payload_size must be >= 8")
    ctrl, bind_host, bind_port = socks5_udp_associate(proxy_host, proxy_port)
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.settimeout(udp_timeout_ms / 1000.0)

    rtts_ms: List[float] = []
    success = 0
    start = time.perf_counter()
    for seq in range(iterations):
        body = struct.pack("!I", seq) + bytes([seq % 251]) * (payload_size - 4)
        req = encode_udp_request(target_host, target_port, body)
        t0 = time.perf_counter_ns()
        udp_sock.sendto(req, (bind_host, bind_port))
        try:
            raw, _ = udp_sock.recvfrom(65535)
            resp = decode_udp_response(raw)
            if len(resp) >= 4 and struct.unpack("!I", resp[:4])[0] == seq:
                t1 = time.perf_counter_ns()
                rtts_ms.append((t1 - t0) / 1_000_000.0)
                success += 1
        except socket.timeout:
            continue
    wall_sec = time.perf_counter() - start

    loss_rate = 1.0 - (success / float(iterations)) if iterations > 0 else 0.0
    total_bytes = success * payload_size

    try:
        udp_sock.close()
    except OSError:
        pass
    try:
        ctrl.close()
    except OSError:
        pass
    return summarize_flow(rtts_ms, total_bytes, wall_sec, loss_rate)


def generate_key_pair(socks_bin: str, build_dir: Path) -> Tuple[str, str]:
    out = subprocess.check_output([socks_bin, "x25519"], cwd=str(build_dir), text=True)
    private_key = ""
    public_key = ""
    for line in out.strip().splitlines():
        lower = line.strip().lower()
        if lower.startswith("private key:") or lower.startswith("private_key:"):
            private_key = line.split(":", 1)[1].strip()
        if lower.startswith("public key:") or lower.startswith("public_key:"):
            public_key = line.split(":", 1)[1].strip()
    if not private_key or not public_key:
        raise RuntimeError(f"failed to parse x25519 output: {out}")
    return private_key, public_key


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def terminate_process(proc: Optional[subprocess.Popen]) -> None:
    if proc is None:
        return
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=3)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SOCKS data-plane baseline benchmark")
    parser.add_argument("--build-dir", default="build", help="build directory path")
    parser.add_argument("--socks-bin", default="./socks", help="socks binary path relative to build dir")
    parser.add_argument("--server-port", type=int, default=21060)
    parser.add_argument("--socks-port", type=int, default=11095)
    parser.add_argument("--tcp-echo-port", type=int, default=19091)
    parser.add_argument("--udp-echo-port", type=int, default=19092)
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--payload-size", type=int, default=1024)
    parser.add_argument("--udp-timeout-ms", type=int, default=300)
    parser.add_argument("--startup-wait-sec", type=float, default=2.0)
    parser.add_argument("--out-json", default="build/perf_baseline_latest.json")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    build_dir = Path(args.build_dir)
    if not build_dir.exists():
        raise RuntimeError(f"build directory not found: {build_dir}")

    private_key, public_key = generate_key_pair(args.socks_bin, build_dir)
    short_id = "0123456789abcdef"
    sni = "perf.baseline.test"

    server_cfg = {
        "mode": "server",
        "log": {"level": "warn", "file": "perf_server.log"},
        "inbound": {"host": "127.0.0.1", "port": args.server_port},
        "reality": {
            "sni": sni,
            "private_key": private_key,
            "public_key": public_key,
            "short_id": short_id,
        },
        "fallbacks": [],
        "timeout": {"idle": 120},
        "limits": {"max_connections": 20000},
    }
    client_cfg = {
        "mode": "client",
        "log": {"level": "warn", "file": "perf_client.log"},
        "inbound": {"host": "127.0.0.1", "port": args.socks_port},
        "outbound": {"host": "127.0.0.1", "port": args.server_port},
        "socks": {"host": "127.0.0.1", "port": args.socks_port, "auth": False},
        "reality": {
            "sni": sni,
            "public_key": public_key,
            "private_key": private_key,
            "short_id": short_id,
        },
        "timeout": {"idle": 120},
        "limits": {"max_connections": 20000},
    }

    server_cfg_name = "perf_server.json"
    client_cfg_name = "perf_client.json"
    write_json(build_dir / server_cfg_name, server_cfg)
    write_json(build_dir / client_cfg_name, client_cfg)

    tcp_echo = TcpEchoServer("127.0.0.1", args.tcp_echo_port)
    udp_echo = UdpEchoServer("127.0.0.1", args.udp_echo_port)
    server_proc: Optional[subprocess.Popen] = None
    client_proc: Optional[subprocess.Popen] = None

    try:
        tcp_echo.start()
        udp_echo.start()

        server_proc = subprocess.Popen(
            [args.socks_bin, "-c", server_cfg_name],
            cwd=str(build_dir),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        client_proc = subprocess.Popen(
            [args.socks_bin, "-c", client_cfg_name],
            cwd=str(build_dir),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        time.sleep(args.startup_wait_sec)
        if server_proc.poll() is not None:
            raise RuntimeError("perf server process exited unexpectedly")
        if client_proc.poll() is not None:
            raise RuntimeError("perf client process exited unexpectedly")

        monitor = ProcessMonitor({server_proc.pid: "server", client_proc.pid: "client"})
        monitor.start()
        bench_start = time.perf_counter()
        tcp_metrics = run_tcp_benchmark(
            proxy_host="127.0.0.1",
            proxy_port=args.socks_port,
            target_host="127.0.0.1",
            target_port=args.tcp_echo_port,
            iterations=args.iterations,
            payload_size=args.payload_size,
        )
        udp_metrics = run_udp_benchmark(
            proxy_host="127.0.0.1",
            proxy_port=args.socks_port,
            target_host="127.0.0.1",
            target_port=args.udp_echo_port,
            iterations=args.iterations,
            payload_size=args.payload_size,
            udp_timeout_ms=args.udp_timeout_ms,
        )
        bench_wall = time.perf_counter() - bench_start
        monitor.stop()
        proc_metrics = monitor.summarize(bench_wall)

        result = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "config": {
                "iterations": args.iterations,
                "payload_size_bytes": args.payload_size,
                "udp_timeout_ms": args.udp_timeout_ms,
            },
            "tcp": tcp_metrics,
            "udp": udp_metrics,
            "process": proc_metrics,
        }
        out_path = Path(args.out_json)
        write_json(out_path, result)

        print(json.dumps(result, indent=2, ensure_ascii=False))
        print(f"[perf-baseline] wrote result to {out_path}")
        return 0
    finally:
        terminate_process(client_proc)
        terminate_process(server_proc)
        tcp_echo.stop()
        udp_echo.stop()


if __name__ == "__main__":
    raise SystemExit(main())
