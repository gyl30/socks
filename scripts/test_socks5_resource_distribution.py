#!/usr/bin/env python3

import argparse
import asyncio
import ipaddress
import json
import os
import random
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path


DEFAULT_PROFILES = {
    "api": "1K:35,4K:30,16K:20,64K:10,256K:4,1M:1",
    "web": "4K:25,16K:25,64K:20,256K:15,1M:10,4M:4,8M:1",
    "download": "64K:10,256K:20,1M:25,4M:25,8M:15,16M:5",
}


class ManagedProcess:
    def __init__(self, process, stdout_handle):
        self.process = process
        self.stdout_handle = stdout_handle

    def terminate(self):
        if self.process.poll() is None:
            self.process.terminate()

    def wait(self, timeout_sec=5):
        try:
            self.process.wait(timeout=timeout_sec)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=timeout_sec)
        self.stdout_handle.close()


class ProcessGroup:
    def __init__(self):
        self.processes = []

    def start(self, args, stdout_path):
        stdout_handle = open(stdout_path, "w", encoding="utf-8")
        process = subprocess.Popen(args, stdout=stdout_handle, stderr=subprocess.STDOUT, text=True)
        managed = ManagedProcess(process, stdout_handle)
        self.processes.append(managed)
        return managed

    def terminate_all(self):
        for managed in reversed(self.processes):
            managed.terminate()
        for managed in reversed(self.processes):
            managed.wait()


def env_int(name, default):
    value = os.getenv(name)
    return int(value) if value is not None else default


def env_bool(name, default):
    value = os.getenv(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def parse_size(text):
    value = text.strip().lower()
    match = re.fullmatch(r"(\d+)([kmg]i?b?|b)?", value)
    if match is None:
        raise ValueError(f"invalid size token {text!r}")
    number = int(match.group(1))
    suffix = match.group(2) or "b"
    multipliers = {
        "b": 1,
        "k": 1024,
        "kb": 1024,
        "kib": 1024,
        "m": 1024 * 1024,
        "mb": 1024 * 1024,
        "mib": 1024 * 1024,
        "g": 1024 * 1024 * 1024,
        "gb": 1024 * 1024 * 1024,
        "gib": 1024 * 1024 * 1024,
    }
    return number * multipliers[suffix]


def format_size(size_bytes):
    if size_bytes % (1024 * 1024) == 0:
        return f"{size_bytes // (1024 * 1024)}MiB"
    if size_bytes % 1024 == 0:
        return f"{size_bytes // 1024}KiB"
    return f"{size_bytes}B"


def parse_profile_spec(spec):
    entries = []
    for part in spec.split(","):
        item = part.strip()
        if not item:
            continue
        if ":" not in item:
            raise ValueError(f"invalid profile item {item!r}, expected SIZE:WEIGHT")
        size_text, weight_text = item.split(":", 1)
        size_bytes = parse_size(size_text)
        weight = int(weight_text.strip())
        if size_bytes <= 0 or weight <= 0:
            raise ValueError(f"invalid profile item {item!r}, size and weight must be positive")
        entries.append({"size_bytes": size_bytes, "weight": weight, "label": format_size(size_bytes)})
    if not entries:
        raise ValueError("profile cannot be empty")
    return entries


def build_connect_request(host, port):
    request = bytearray(b"\x05\x01\x00")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        encoded_host = host.encode("utf-8")
        if not encoded_host or len(encoded_host) > 255:
            raise RuntimeError("invalid domain host")
        request.append(0x03)
        request.append(len(encoded_host))
        request.extend(encoded_host)
    else:
        request.append(0x01 if address.version == 4 else 0x04)
        request.extend(address.packed)
    request.extend(struct.pack("!H", port))
    return bytes(request)


async def recv_exact(reader, size):
    return await reader.readexactly(size)


async def recv_socks_reply(reader):
    head = await recv_exact(reader, 4)
    atyp = head[3]
    if atyp == 0x01:
        tail = await recv_exact(reader, 6)
    elif atyp == 0x04:
        tail = await recv_exact(reader, 18)
    elif atyp == 0x03:
        domain_len = (await recv_exact(reader, 1))[0]
        tail = bytes([domain_len]) + await recv_exact(reader, domain_len + 2)
    else:
        raise RuntimeError(f"unsupported atyp {atyp}")
    return head + tail


async def read_http_response(reader):
    header = bytearray()
    while b"\r\n\r\n" not in header:
        chunk = await reader.read(4096)
        if not chunk:
            raise RuntimeError("unexpected eof before response header")
        header.extend(chunk)
        if len(header) > 65536:
            raise RuntimeError("response header too large")

    header_end = header.index(b"\r\n\r\n") + 4
    raw_header = bytes(header[:header_end])
    body = bytearray(header[header_end:])
    header_text = raw_header.decode("iso-8859-1")
    lines = header_text.split("\r\n")
    if not lines or not lines[0].startswith("HTTP/1."):
        raise RuntimeError(f"invalid status line {lines[:1]}")
    parts = lines[0].split()
    if len(parts) < 2 or parts[1] != "200":
        raise RuntimeError(f"unexpected status line {lines[0]}")

    content_length = None
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key.lower() == "content-length":
            content_length = int(value.strip())
            break
    if content_length is None:
        raise RuntimeError("missing content-length")

    while len(body) < content_length:
        chunk = await reader.read(content_length - len(body))
        if not chunk:
            raise RuntimeError("unexpected eof before response body")
        body.extend(chunk)
    return content_length


async def run_request(load_args, path):
    reader, writer = await asyncio.open_connection(load_args.socks_host, load_args.socks_port)
    try:
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        method_reply = await recv_exact(reader, 2)
        if method_reply != b"\x05\x00":
            raise RuntimeError(f"unexpected method reply {method_reply!r}")

        writer.write(build_connect_request(load_args.target_host, load_args.target_port))
        await writer.drain()
        reply = await recv_socks_reply(reader)
        if reply[1] != 0x00:
            raise RuntimeError(f"connect failed rep={reply[1]}")

        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {load_args.target_host}:{load_args.target_port}\r\n"
            "Connection: close\r\n"
            "User-Agent: socks5-profile-load-test\r\n"
            "\r\n"
        ).encode("utf-8")
        writer.write(request)
        await writer.drain()
        return await read_http_response(reader)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def sleep_with_jitter(rnd, min_delay_ms, max_delay_ms):
    if max_delay_ms <= 0:
        return
    delay_ms = rnd.uniform(min_delay_ms, max_delay_ms)
    if delay_ms > 0:
        await asyncio.sleep(delay_ms / 1000.0)


async def worker(worker_id, load_args, planned_sizes):
    total_bytes = 0
    counts = Counter()
    rnd = random.Random(load_args.seed + worker_id * 1000003 + 17)
    await sleep_with_jitter(rnd, 0, load_args.worker_start_jitter_ms)
    for index, size_bytes in enumerate(planned_sizes):
        path = f"/payload-{size_bytes}.bin"
        total_bytes += await run_request(load_args, path)
        counts[size_bytes] += 1
        if index + 1 != len(planned_sizes):
            await sleep_with_jitter(rnd, load_args.request_gap_min_ms, load_args.request_gap_max_ms)
    return worker_id, total_bytes, counts


def build_request_plan(entries, total_requests, seed):
    sizes = [entry["size_bytes"] for entry in entries]
    weights = [entry["weight"] for entry in entries]
    rnd = random.Random(seed)
    return rnd.choices(sizes, weights=weights, k=total_requests)


def allocate_ports(count):
    sockets = []
    ports = []
    for _ in range(count):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        sockets.append(sock)
        ports.append(sock.getsockname()[1])
    for sock in sockets:
        sock.close()
    return ports


def run_command(args, cwd):
    result = subprocess.run(args, cwd=cwd, text=True, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed {' '.join(args)}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result.stdout


def parse_key_output(output):
    private_match = re.search(r"private key:\s+(\S+)", output)
    public_match = re.search(r"public key:\s+(\S+)", output)
    if private_match is None or public_match is None:
        raise RuntimeError("failed to parse x25519 key output")
    return private_match.group(1), public_match.group(1)


def port_is_listening(port):
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                next(handle, None)
                for line in handle:
                    fields = line.split()
                    if len(fields) < 4:
                        continue
                    local_address = fields[1]
                    state = fields[3]
                    if state != "0A":
                        continue
                    try:
                        _addr_hex, port_hex = local_address.rsplit(":", 1)
                    except ValueError:
                        continue
                    if int(port_hex, 16) == port:
                        return True
        except FileNotFoundError:
            continue
    return False


def wait_for_port(port, name, owners):
    deadline = time.time() + 10.0
    while time.time() < deadline:
        for owner in owners:
            if owner.process.poll() is not None:
                raise RuntimeError(f"{name} owner process exited early")
        if port_is_listening(port):
            return
        time.sleep(0.1)
    raise RuntimeError(f"timeout waiting for {name} 127.0.0.1:{port}")


def wait_for_proxy_ready(load_args, path, owners, deadline_seconds=20.0):
    deadline = time.time() + deadline_seconds
    last_error = None

    while time.time() < deadline:
        for owner in owners:
            if owner.process.poll() is not None:
                raise RuntimeError("proxy owner process exited early")
        try:
            asyncio.run(run_request(load_args, path))
            return
        except Exception as exc:
            last_error = exc
            time.sleep(0.2)

    raise RuntimeError(f"timeout waiting for socks5 proxy ready last_error={last_error}")


def write_json(path, data):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


def create_payload(path, size_bytes):
    chunk = (b"socks5-resource-profile-" * 2048)[:65536]
    remaining = size_bytes
    with open(path, "wb") as handle:
        while remaining > 0:
            piece = chunk[: min(len(chunk), remaining)]
            handle.write(piece)
            remaining -= len(piece)


def tail_logs(tmp_dir):
    for log_path in sorted(tmp_dir.glob("*.log")):
        print(f"===== {log_path.name} =====", file=sys.stderr)
        with open(log_path, "r", encoding="utf-8") as handle:
            for line in handle.readlines()[-80:]:
                sys.stderr.write(line)


def print_resource_summary(resource_summary):
    for label in ("client", "server"):
        proc = resource_summary["processes"][label]
        print(
            f"{label} peak_rss_kb={proc['peak_rss_kb']} "
            f"peak_fd_count={proc['peak_fd_count']} "
            f"peak_threads={proc['peak_threads']} "
            f"cpu_seconds_total={proc['cpu_seconds_total']:.3f}"
        )


def check_thresholds(resource_summary):
    thresholds = {
        "client": {
            "rss_kb": os.getenv("MAX_CLIENT_RSS_KB"),
            "fd_count": os.getenv("MAX_CLIENT_FD"),
        },
        "server": {
            "rss_kb": os.getenv("MAX_SERVER_RSS_KB"),
            "fd_count": os.getenv("MAX_SERVER_FD"),
        },
    }
    for label, values in thresholds.items():
        proc = resource_summary["processes"][label]
        if values["rss_kb"] is not None and proc["peak_rss_kb"] > int(values["rss_kb"]):
            raise RuntimeError(f"{label} peak rss exceeded threshold")
        if values["fd_count"] is not None and proc["peak_fd_count"] > int(values["fd_count"]):
            raise RuntimeError(f"{label} peak fd exceeded threshold")


def build_server_config(tmp_dir, server_port, private_key, public_key, short_id, sni, args):
    return {
        "workers": args.server_workers,
        "log": {
            "level": "info",
            "file": str(tmp_dir / "server.log"),
        },
        "inbounds": [
            {
                "type": "reality",
                "tag": "reality-in",
                "settings": {
                    "host": "127.0.0.1",
                    "port": server_port,
                    "sni": sni,
                    "private_key": private_key,
                    "public_key": public_key,
                    "short_id": short_id,
                    "replay_cache_max_entries": 100000,
                },
            }
        ],
        "outbounds": [
            {
                "type": "direct",
                "tag": "direct",
            },
            {
                "type": "block",
                "tag": "block",
            },
        ],
        "routing": [
            {
                "type": "inbound",
                "values": ["reality-in"],
                "out": "direct",
            }
        ],
        "timeout": {
            "read": args.read_timeout_sec,
            "write": args.write_timeout_sec,
            "connect": args.connect_timeout_sec,
            "idle": args.idle_timeout_sec,
        },
    }


def build_client_config(tmp_dir, socks_port, server_port, public_key, short_id, sni, args):
    return {
        "workers": args.client_workers,
        "log": {
            "level": "info",
            "file": str(tmp_dir / "client.log"),
        },
        "inbounds": [
            {
                "type": "socks",
                "tag": "socks-in",
                "settings": {
                    "host": "127.0.0.1",
                    "port": socks_port,
                    "auth": False,
                },
            }
        ],
        "outbounds": [
            {
                "type": "reality",
                "tag": "reality-out",
                "settings": {
                    "host": "127.0.0.1",
                    "port": server_port,
                    "sni": sni,
                    "fingerprint": "random",
                    "public_key": public_key,
                    "short_id": short_id,
                    "max_handshake_records": args.client_max_handshake_records,
                },
            },
            {
                "type": "direct",
                "tag": "direct",
            },
            {
                "type": "block",
                "tag": "block",
            },
        ],
        "routing": [
            {
                "type": "inbound",
                "values": ["socks-in"],
                "out": "reality-out",
            }
        ],
        "timeout": {
            "read": args.read_timeout_sec,
            "write": args.write_timeout_sec,
            "connect": args.connect_timeout_sec,
            "idle": args.idle_timeout_sec,
        },
    }


async def run_profile_load(load_args, entries):
    total_requests = load_args.concurrency * load_args.requests_per_worker
    request_plan = build_request_plan(entries, total_requests, load_args.seed)
    started_at = time.perf_counter()
    tasks = []
    for worker_id in range(load_args.concurrency):
        begin = worker_id * load_args.requests_per_worker
        end = begin + load_args.requests_per_worker
        worker_sizes = request_plan[begin:end]
        tasks.append(asyncio.create_task(worker(worker_id, load_args, worker_sizes)))
    results = await asyncio.gather(*tasks)
    duration = time.perf_counter() - started_at

    total_bytes = 0
    observed_counts = Counter()
    for _worker_id, worker_bytes, counts in results:
        total_bytes += worker_bytes
        observed_counts.update(counts)

    throughput = (total_bytes / (1024.0 * 1024.0)) / duration if duration > 0 else 0.0
    profile_counts = {format_size(size): observed_counts[size] for size in sorted(observed_counts)}
    return {
        "connections": total_requests,
        "bytes": total_bytes,
        "duration_seconds": duration,
        "throughput_mib_per_s": throughput,
        "request_counts_by_size": profile_counts,
    }


def parse_args():
    parser = argparse.ArgumentParser(description="Run SOCKS5 resource test with a mixed response-size distribution")
    parser.add_argument("--binary", default=str(Path("build") / "socks"), help="path to socks binary")
    parser.add_argument("--profile-name", choices=sorted(DEFAULT_PROFILES), default=os.getenv("PROFILE_NAME", "web"))
    parser.add_argument("--profile", default=os.getenv("RESPONSE_SIZE_PROFILE", ""), help="SIZE:WEIGHT comma list")
    parser.add_argument("--seed", type=int, default=env_int("PROFILE_SEED", 20260322))
    parser.add_argument("--keep-artifacts", action="store_true", default=env_bool("KEEP_TEST_ARTIFACTS", False))
    parser.add_argument("--concurrency", type=int, default=env_int("CONCURRENCY", 32))
    parser.add_argument("--requests-per-worker", type=int, default=env_int("REQUESTS_PER_WORKER", 4))
    parser.add_argument("--client-workers", type=int, default=env_int("CLIENT_WORKERS", 8))
    parser.add_argument("--server-workers", type=int, default=env_int("SERVER_WORKERS", 8))
    parser.add_argument("--read-timeout-sec", type=int, default=env_int("READ_TIMEOUT_SEC", 10))
    parser.add_argument("--write-timeout-sec", type=int, default=env_int("WRITE_TIMEOUT_SEC", 10))
    parser.add_argument("--connect-timeout-sec", type=int, default=env_int("CONNECT_TIMEOUT_SEC", 5))
    parser.add_argument("--idle-timeout-sec", type=int, default=env_int("IDLE_TIMEOUT_SEC", 60))
    parser.add_argument("--client-max-handshake-records", type=int, default=env_int("CLIENT_MAX_HANDSHAKE_RECORDS", 256))
    parser.add_argument("--server-max-handshake-records", type=int, default=env_int("SERVER_MAX_HANDSHAKE_RECORDS", 256))
    parser.add_argument("--monitor-interval-ms", type=int, default=env_int("MONITOR_INTERVAL_MS", 50))
    parser.add_argument("--worker-start-jitter-ms", type=int, default=env_int("WORKER_START_JITTER_MS", 0))
    parser.add_argument("--request-gap-min-ms", type=int, default=env_int("REQUEST_GAP_MIN_MS", 0))
    parser.add_argument("--request-gap-max-ms", type=int, default=env_int("REQUEST_GAP_MAX_MS", 0))
    args = parser.parse_args()
    if args.worker_start_jitter_ms < 0:
        raise ValueError("worker start jitter must be non-negative")
    if args.request_gap_min_ms < 0 or args.request_gap_max_ms < 0:
        raise ValueError("request gap jitter must be non-negative")
    if args.request_gap_max_ms < args.request_gap_min_ms:
        raise ValueError("request gap max jitter must be >= min jitter")
    return args


def main():
    args = parse_args()
    profile_name = args.profile_name if not args.profile else "custom"
    profile_spec = args.profile or DEFAULT_PROFILES[args.profile_name]
    entries = parse_profile_spec(profile_spec)

    repo_root = Path(__file__).resolve().parents[1]
    binary = Path(args.binary)
    if not binary.is_absolute():
        binary = (repo_root / binary).resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError(f"binary not found: {binary}")

    tmp_dir = Path(tempfile.mkdtemp(prefix=".tmp-socks5-resource-dist.", dir=repo_root))
    process_group = ProcessGroup()
    success = False
    monitor = None
    try:
        server_port, socks_port, http_port = allocate_ports(3)
        key_output = run_command([str(binary), "x25519"], cwd=repo_root)
        private_key, public_key = parse_key_output(key_output)
        short_id = "0102030405060708"
        sni = "www.example.com"

        write_json(tmp_dir / "server.json", build_server_config(tmp_dir, server_port, private_key, public_key, short_id, sni, args))
        write_json(tmp_dir / "client.json", build_client_config(tmp_dir, socks_port, server_port, public_key, short_id, sni, args))

        http_dir = tmp_dir / "http"
        http_dir.mkdir(parents=True, exist_ok=True)
        payload_manifest = {}
        for entry in entries:
            payload_path = http_dir / f"payload-{entry['size_bytes']}.bin"
            if not payload_path.exists():
                create_payload(payload_path, entry["size_bytes"])
            payload_manifest[entry["label"]] = {
                "size_bytes": entry["size_bytes"],
                "weight": entry["weight"],
                "path": f"/{payload_path.name}",
            }
        write_json(tmp_dir / "payload-profile.json", {"profile_name": profile_name, "profile_spec": profile_spec, "entries": payload_manifest})

        http_server = process_group.start(
            [sys.executable, "-m", "http.server", str(http_port), "--bind", "127.0.0.1", "--directory", str(http_dir)],
            tmp_dir / "http.log",
        )
        server = process_group.start([str(binary), "-c", str(tmp_dir / "server.json")], tmp_dir / "server.stdout.log")
        wait_for_port(server_port, "reality_server", [server])
        client = process_group.start([str(binary), "-c", str(tmp_dir / "client.json")], tmp_dir / "client.stdout.log")
        wait_for_port(http_port, "http_server", [http_server])
        wait_for_port(socks_port, "socks5_listener", [server, client])
        smallest_entry = min(entries, key=lambda entry: entry["size_bytes"])
        probe_args = argparse.Namespace(
            socks_host="127.0.0.1",
            socks_port=socks_port,
            target_host="127.0.0.1",
            target_port=http_port,
        )
        wait_for_proxy_ready(probe_args, f"/payload-{smallest_entry['size_bytes']}.bin", [server, client])

        resource_summary_path = tmp_dir / "resource-summary.json"
        monitor = process_group.start(
            [
                sys.executable,
                str(repo_root / "scripts/process_resource_monitor.py"),
                "--pid",
                f"client:{client.process.pid}",
                "--pid",
                f"server:{server.process.pid}",
                "--interval-ms",
                str(args.monitor_interval_ms),
                "--output",
                str(resource_summary_path),
            ],
            tmp_dir / "resource-monitor.log",
        )
        time.sleep(max(0.05, args.monitor_interval_ms / 1000.0))

        load_args = argparse.Namespace(
            socks_host="127.0.0.1",
            socks_port=socks_port,
            target_host="127.0.0.1",
            target_port=http_port,
            concurrency=args.concurrency,
            requests_per_worker=args.requests_per_worker,
            seed=args.seed,
            worker_start_jitter_ms=args.worker_start_jitter_ms,
            request_gap_min_ms=args.request_gap_min_ms,
            request_gap_max_ms=args.request_gap_max_ms,
        )
        load_summary = asyncio.run(run_profile_load(load_args, entries))
        with open(tmp_dir / "load-summary.log", "w", encoding="utf-8") as handle:
            handle.write(f"connections={load_summary['connections']}\n")
            handle.write(f"bytes={load_summary['bytes']}\n")
            handle.write(f"duration_seconds={load_summary['duration_seconds']:.3f}\n")
            handle.write(f"throughput_mib_per_s={load_summary['throughput_mib_per_s']:.2f}\n")
            handle.write(f"profile_name={profile_name}\n")
            handle.write(f"profile_spec={profile_spec}\n")
            handle.write(f"seed={args.seed}\n")
            handle.write(f"worker_start_jitter_ms={args.worker_start_jitter_ms}\n")
            handle.write(f"request_gap_min_ms={args.request_gap_min_ms}\n")
            handle.write(f"request_gap_max_ms={args.request_gap_max_ms}\n")
            handle.write(
                "request_counts_by_size_json={}\n".format(
                    json.dumps(load_summary["request_counts_by_size"], sort_keys=True, separators=(",", ":"))
                )
            )

        print(f"connections={load_summary['connections']}")
        print(f"bytes={load_summary['bytes']}")
        print(f"duration_seconds={load_summary['duration_seconds']:.3f}")
        print(f"throughput_mib_per_s={load_summary['throughput_mib_per_s']:.2f}")
        print(f"profile_name={profile_name}")
        print(f"profile_spec={profile_spec}")
        print(f"seed={args.seed}")
        print(f"worker_start_jitter_ms={args.worker_start_jitter_ms}")
        print(f"request_gap_min_ms={args.request_gap_min_ms}")
        print(f"request_gap_max_ms={args.request_gap_max_ms}")
        print(
            "request_counts_by_size_json={}".format(
                json.dumps(load_summary["request_counts_by_size"], sort_keys=True, separators=(",", ":"))
            )
        )

        if monitor is not None:
            monitor.terminate()
            monitor.wait()
            process_group.processes.remove(monitor)
            monitor = None

        if not resource_summary_path.exists():
            raise RuntimeError(f"resource monitor did not produce {resource_summary_path.name}")
        with open(resource_summary_path, "r", encoding="utf-8") as handle:
            resource_summary = json.load(handle)
        print_resource_summary(resource_summary)
        check_thresholds(resource_summary)
        success = True
    except Exception as exc:
        print(f"resource distribution test failed: {exc}", file=sys.stderr)
        tail_logs(tmp_dir)
        raise
    finally:
        if monitor is not None:
            monitor.terminate()
            monitor.wait()
            process_group.processes.remove(monitor)
        process_group.terminate_all()
        if success:
            if args.keep_artifacts:
                print(f"resource test artifacts kept at {tmp_dir}")
            else:
                shutil.rmtree(tmp_dir)
        else:
            print(f"resource test failed logs kept at {tmp_dir}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
