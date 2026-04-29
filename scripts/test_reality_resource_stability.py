#!/usr/bin/env python3

import argparse
import json
import os
import pathlib
import shutil
import socket
import struct
import sys
import tempfile
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from testlib import (
    allocate_tcp_port,
    allocate_udp_port,
    build_runtime_env,
    parse_key_output,
    run_checked,
    save_json,
    start_process,
    tail_file,
    wait_for_log_text,
    wait_for_port,
)


def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError(f"unexpected eof while reading {size} bytes")
        data.extend(chunk)
    return bytes(data)


def parse_socks_address(sock):
    atyp = recv_exact(sock, 1)[0]
    if atyp == 0x01:
        host = socket.inet_ntoa(recv_exact(sock, 4))
    elif atyp == 0x03:
        host_len = recv_exact(sock, 1)[0]
        host = recv_exact(sock, host_len).decode("utf-8")
    elif atyp == 0x04:
        host = socket.inet_ntop(socket.AF_INET6, recv_exact(sock, 16))
    else:
        raise RuntimeError(f"unsupported atyp {atyp}")
    port = struct.unpack("!H", recv_exact(sock, 2))[0]
    return host, port


def build_socks_connect_request(host, port):
    request = bytearray(b"\x05\x01\x00")
    request.append(0x01)
    request.extend(socket.inet_aton(host))
    request.extend(struct.pack("!H", port))
    return bytes(request)


def encode_socks_udp_header(host, port):
    header = bytearray(b"\x00\x00\x00\x01")
    header.extend(socket.inet_aton(host))
    header.extend(struct.pack("!H", port))
    return bytes(header)


def decode_socks_udp_packet(packet):
    if len(packet) < 10:
        raise RuntimeError("udp packet too short")
    if packet[:4] != b"\x00\x00\x00\x01":
        raise RuntimeError(f"invalid udp packet header {packet[:4]!r}")
    host = socket.inet_ntoa(packet[4:8])
    port = struct.unpack("!H", packet[8:10])[0]
    return host, port, packet[10:]


def perform_socks_connect(socks_host, socks_port, target_host, target_port, timeout=5.0):
    sock = socket.create_connection((socks_host, socks_port), timeout=timeout)
    sock.settimeout(timeout)
    sock.sendall(b"\x05\x01\x00")
    method_reply = recv_exact(sock, 2)
    if method_reply != b"\x05\x00":
        raise RuntimeError(f"unexpected method reply {method_reply!r}")
    sock.sendall(build_socks_connect_request(target_host, target_port))
    version, rep, _rsv = recv_exact(sock, 3)
    if version != 0x05 or rep != 0x00:
        raise RuntimeError(f"socks connect failed version={version} rep={rep}")
    parse_socks_address(sock)
    return sock


def run_short_tcp_case(socks_host, socks_port, target_host, target_port, payload, expected_reply):
    sock = perform_socks_connect(socks_host, socks_port, target_host, target_port)
    try:
        sock.sendall(payload)
        reply = recv_exact(sock, len(expected_reply))
        if reply != expected_reply:
            raise RuntimeError(f"unexpected short reply {reply!r}")
    finally:
        sock.close()


def run_half_close_case(socks_host, socks_port, target_host, target_port, payload, expected_reply):
    sock = perform_socks_connect(socks_host, socks_port, target_host, target_port)
    try:
        sock.sendall(payload)
        sock.shutdown(socket.SHUT_WR)
        reply = recv_exact(sock, len(expected_reply))
        if reply != expected_reply:
            raise RuntimeError(f"unexpected half-close reply {reply!r}")
    finally:
        sock.close()


def run_udp_echo_case(socks_host, socks_port, target_host, target_port, payload, timeout=5.0):
    tcp_sock = socket.create_connection((socks_host, socks_port), timeout=timeout)
    tcp_sock.settimeout(timeout)
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.settimeout(timeout)
    try:
        tcp_sock.sendall(b"\x05\x01\x00")
        method_reply = recv_exact(tcp_sock, 2)
        if method_reply != b"\x05\x00":
            raise RuntimeError(f"unexpected method reply {method_reply!r}")
        tcp_sock.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        version, rep, _rsv = recv_exact(tcp_sock, 3)
        if version != 0x05 or rep != 0x00:
            raise RuntimeError(f"udp associate failed version={version} rep={rep}")
        relay_host, relay_port = parse_socks_address(tcp_sock)
        udp_sock.sendto(encode_socks_udp_header(target_host, target_port) + payload, (relay_host, relay_port))
        response, _peer = udp_sock.recvfrom(65535)
        source_host, source_port, response_payload = decode_socks_udp_packet(response)
        if source_host != target_host or source_port != target_port:
            raise RuntimeError(f"unexpected udp source {source_host}:{source_port}")
        if response_payload != payload:
            raise RuntimeError(f"udp payload mismatch len={len(response_payload)} expected={len(payload)}")
    finally:
        udp_sock.close()
        tcp_sock.close()


def fetch_json(url):
    with urllib.request.urlopen(url, timeout=2) as response:
        return json.load(response)


class ConcurrentTcpServer:
    def __init__(self, mode, response_payload=b""):
        self.mode = mode
        self.response_payload = response_payload
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen()
        self.server.settimeout(0.2)
        self.host, self.port = self.server.getsockname()
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.accept_thread = threading.Thread(target=self._serve, daemon=True)
        self.handler_threads = []
        self.errors = []
        self.received_count = 0
        self.saw_eof_count = 0
        self.accept_thread.start()

    def close(self):
        self.stop_event.set()
        try:
            self.server.close()
        except OSError:
            pass

    def join(self):
        self.close()
        self.accept_thread.join(timeout=5)
        if self.accept_thread.is_alive():
            raise RuntimeError(f"{self.mode} tcp server accept loop did not exit")
        for thread in self.handler_threads:
            thread.join(timeout=5)
            if thread.is_alive():
                raise RuntimeError(f"{self.mode} tcp server handler did not exit")
        if self.errors:
            raise self.errors[0]

    def _serve(self):
        try:
            while not self.stop_event.is_set():
                try:
                    conn, _peer = self.server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self.stop_event.is_set():
                        return
                    raise
                thread = threading.Thread(target=self._handle_client, args=(conn,), daemon=True)
                self.handler_threads.append(thread)
                thread.start()
        except Exception as exc:
            self.errors.append(exc)

    def _handle_client(self, conn):
        try:
            with conn:
                conn.settimeout(10)
                if self.mode == "reply":
                    payload = conn.recv(4096)
                    if not payload:
                        raise RuntimeError("reply server received eof before payload")
                    with self.lock:
                        self.received_count += 1
                    conn.sendall(self.response_payload)
                    return

                while True:
                    payload = conn.recv(4096)
                    if not payload:
                        with self.lock:
                            self.saw_eof_count += 1
                            if self.mode == "half-close":
                                self.received_count += 1
                        break
                if self.mode == "half-close":
                    conn.sendall(self.response_payload)
        except Exception as exc:
            with self.lock:
                self.errors.append(exc)


def run_parallel(total, concurrency, fn):
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(fn, index) for index in range(total)]
        for future in futures:
            future.result()


def wait_for_idle_close_events(web_port, target_port, expected_count, minimum_duration_ms):
    deadline = time.time() + 5.0
    matches = []
    while time.time() < deadline:
        payload = fetch_json(f"http://127.0.0.1:{web_port}/api/traces/events?stage=session_close&limit=500")
        events = payload.get("items") or payload.get("events") or []
        matches = [
            event
            for event in events
            if event.get("inbound_type") == "socks"
            and event.get("route_type") == "reality-out"
            and event.get("target_port") == target_port
            and event.get("extra", {}).get("close_reason") == "stopped"
            and int(event.get("extra", {}).get("duration_ms", "0")) >= minimum_duration_ms
        ]
        if len(matches) >= expected_count:
            return matches
        time.sleep(0.1)
    raise RuntimeError(f"missing idle cleanup close events count={len(matches)} expected={expected_count}")


def read_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def assert_resource_cleanup(summary):
    for label in ("client", "server"):
        proc = summary["processes"][label]
        initial_fd_count = proc["initial"]["fd_count"]
        final_fd_count = proc["final"]["fd_count"]
        initial_threads = proc["initial"]["threads"]
        final_threads = proc["final"]["threads"]
        if proc["sample_count"] < 10:
            raise RuntimeError(f"{label} resource sample count too small: {proc['sample_count']}")
        if final_fd_count > initial_fd_count + 8:
            raise RuntimeError(
                f"{label} final fd count did not return near baseline "
                f"initial={initial_fd_count} final={final_fd_count}"
            )
        if final_threads > initial_threads + 2:
            raise RuntimeError(
                f"{label} final thread count did not return near baseline "
                f"initial={initial_threads} final={final_threads}"
            )


def main():
    parser = argparse.ArgumentParser(description="Reality protocol resource and stability regression")
    parser.add_argument("--binary", default=str(pathlib.Path("build") / "socks"), help="path to the socks binary")
    parser.add_argument("--keep-artifacts", action="store_true")
    args = parser.parse_args()

    repo_root = pathlib.Path(__file__).resolve().parents[1]
    binary = pathlib.Path(args.binary)
    if not binary.is_absolute():
        binary = (repo_root / binary).resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError(f"binary not found: {binary}")

    if shutil.which("python3") is None:
        raise RuntimeError("missing dependency: python3")

    temp_root = pathlib.Path(tempfile.mkdtemp(prefix=".tmp-reality-resource-stability.", dir=repo_root))
    helper_processes = []
    short_server = None
    half_close_server = None
    idle_server = None
    try:
        runtime_env = build_runtime_env(binary)
        socks_port = allocate_tcp_port()
        web_port = allocate_tcp_port()
        reality_server_port = allocate_tcp_port()
        udp_echo_port = allocate_udp_port()
        short_id = "0102030405060708"
        sni = "www.example.com"

        key_output = run_checked([str(binary), "x25519"], env=runtime_env, capture_output=True)
        private_key, public_key = parse_key_output(key_output.stdout)

        server_log = temp_root / "server.log"
        client_log = temp_root / "client.log"
        udp_log = temp_root / "udp.log"
        monitor_path = temp_root / "resource-summary.json"

        short_server = ConcurrentTcpServer("reply", b"short-ok")
        half_close_server = ConcurrentTcpServer("half-close", b"half-close-ok")
        idle_server = ConcurrentTcpServer("idle")

        udp_process = start_process(
            [
                sys.executable,
                str(repo_root / "scripts/socks5_udp_echo_server.py"),
                "--host",
                "127.0.0.1",
                "--port",
                str(udp_echo_port),
            ],
            str(udp_log),
        )
        helper_processes.append(udp_process)

        server_cfg = {
            "workers": 2,
            "log": {
                "level": "debug",
                "file": str(server_log),
            },
            "timeout": {
                "read": 5,
                "write": 5,
                "connect": 5,
                "idle": 3,
            },
            "inbounds": [
                {
                    "type": "reality",
                    "tag": "reality-in",
                    "settings": {
                        "host": "127.0.0.1",
                        "port": reality_server_port,
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
        }

        client_cfg = {
            "workers": 2,
            "log": {
                "level": "debug",
                "file": str(client_log),
            },
            "timeout": {
                "read": 5,
                "write": 5,
                "connect": 5,
                "idle": 3,
            },
            "web": {
                "enabled": True,
                "host": "127.0.0.1",
                "port": web_port,
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
                        "port": reality_server_port,
                        "sni": sni,
                        "fingerprint": "random",
                        "public_key": public_key,
                        "short_id": short_id,
                        "max_handshake_records": 256,
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
        }

        save_json(temp_root / "server.json", server_cfg)
        save_json(temp_root / "client.json", client_cfg)

        server_process = start_process(
            [str(binary), "-c", str(temp_root / "server.json")],
            str(temp_root / "server.stdout.log"),
            extra_env=runtime_env,
        )
        client_process = start_process(
            [str(binary), "-c", str(temp_root / "client.json")],
            str(temp_root / "client.stdout.log"),
            extra_env=runtime_env,
        )
        helper_processes.extend([server_process, client_process])

        wait_for_log_text(server_log, f"listen 127.0.0.1:{reality_server_port} reality inbound listening", 20, "reality server log")
        wait_for_port("127.0.0.1", reality_server_port, 20, "reality server port", [server_process])
        wait_for_log_text(client_log, f":{socks_port} socks listening", 20, "client socks port")
        wait_for_port("127.0.0.1", socks_port, 20, "socks port", [client_process])
        wait_for_port("127.0.0.1", web_port, 20, "client trace web", [client_process])

        monitor_process = start_process(
            [
                sys.executable,
                str(repo_root / "scripts/process_resource_monitor.py"),
                "--pid",
                f"client:{client_process.process.pid}",
                "--pid",
                f"server:{server_process.process.pid}",
                "--interval-ms",
                "100",
                "--output",
                str(monitor_path),
            ],
            str(temp_root / "resource-monitor.log"),
        )
        helper_processes.append(monitor_process)

        run_parallel(
            48,
            12,
            lambda index: run_short_tcp_case(
                "127.0.0.1",
                socks_port,
                short_server.host,
                short_server.port,
                f"short-{index}".encode("utf-8"),
                b"short-ok",
            ),
        )
        if short_server.received_count != 48:
            raise RuntimeError(f"short connection count mismatch {short_server.received_count}")

        run_parallel(
            24,
            8,
            lambda index: run_half_close_case(
                "127.0.0.1",
                socks_port,
                half_close_server.host,
                half_close_server.port,
                f"half-close-{index}".encode("utf-8"),
                b"half-close-ok",
            ),
        )
        if half_close_server.received_count != 24 or half_close_server.saw_eof_count != 24:
            raise RuntimeError(
                f"half-close count mismatch received={half_close_server.received_count} eof={half_close_server.saw_eof_count}"
            )

        run_parallel(
            48,
            12,
            lambda index: run_udp_echo_case(
                "127.0.0.1",
                socks_port,
                "127.0.0.1",
                udp_echo_port,
                f"udp-{index}".encode("utf-8"),
            ),
        )

        idle_sockets = [
            perform_socks_connect("127.0.0.1", socks_port, idle_server.host, idle_server.port, timeout=5.0)
            for _ in range(6)
        ]
        try:
            time.sleep(4.5)
            for idle_sock in idle_sockets:
                idle_sock.settimeout(1.0)
                data = idle_sock.recv(1)
                if data:
                    raise RuntimeError(f"unexpected idle payload {data!r}")
        finally:
            for idle_sock in idle_sockets:
                idle_sock.close()

        if idle_server.saw_eof_count < 6:
            deadline = time.time() + 2.0
            while time.time() < deadline and idle_server.saw_eof_count < 6:
                time.sleep(0.1)
        if idle_server.saw_eof_count != 6:
            raise RuntimeError(f"idle cleanup eof count mismatch {idle_server.saw_eof_count}")

        wait_for_idle_close_events(web_port, idle_server.port, 6, 3000)

        run_short_tcp_case("127.0.0.1", socks_port, short_server.host, short_server.port, b"final-health", b"short-ok")
        run_half_close_case(
            "127.0.0.1", socks_port, half_close_server.host, half_close_server.port, b"final-half-close", b"half-close-ok"
        )
        run_udp_echo_case("127.0.0.1", socks_port, "127.0.0.1", udp_echo_port, b"final-udp-health")

        time.sleep(0.5)
        monitor_process.terminate()
        resource_summary = read_json(monitor_path)
        assert_resource_cleanup(resource_summary)

        print("short_connection_churn ok")
        print("tcp_half_close_churn ok")
        print("udp_session_churn ok")
        print("idle_cleanup ok")
        for label in ("client", "server"):
            proc = resource_summary["processes"][label]
            print(
                f"{label}_resources initial_fd={proc['initial']['fd_count']} "
                f"peak_fd={proc['peak_fd_count']} final_fd={proc['final']['fd_count']} "
                f"initial_threads={proc['initial']['threads']} final_threads={proc['final']['threads']}"
            )
        return 0
    except Exception as exc:
        print(f"test failed {exc}", file=sys.stderr)
        print("===== server.log =====", file=sys.stderr)
        print(tail_file(temp_root / "server.log"), file=sys.stderr)
        print("===== client.log =====", file=sys.stderr)
        print(tail_file(temp_root / "client.log"), file=sys.stderr)
        print("===== udp.log =====", file=sys.stderr)
        print(tail_file(temp_root / "udp.log"), file=sys.stderr)
        raise
    finally:
        for process in reversed(helper_processes):
            process.terminate()
        for server in (short_server, half_close_server, idle_server):
            if server is not None:
                server.join()
        if args.keep_artifacts:
            print(f"artifacts kept at {temp_root}", file=sys.stderr)
        else:
            shutil.rmtree(temp_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
