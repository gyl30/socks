#!/usr/bin/env python3

import argparse
import ipaddress
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
    addr = ipaddress.ip_address(host)
    if addr.version == 4:
        request.append(0x01)
    else:
        request.append(0x04)
    request.extend(addr.packed)
    request.extend(struct.pack("!H", port))
    return bytes(request)


def encode_socks_udp_header(host, port):
    addr = ipaddress.ip_address(host)
    header = bytearray(b"\x00\x00\x00")
    if addr.version == 4:
        header.append(0x01)
    else:
        header.append(0x04)
    header.extend(addr.packed)
    header.extend(struct.pack("!H", port))
    return bytes(header)


def decode_socks_udp_packet(packet):
    if len(packet) < 10:
        raise RuntimeError("udp packet too short")
    if packet[0] != 0 or packet[1] != 0 or packet[2] != 0:
        raise RuntimeError(f"invalid udp packet header {packet[:3]!r}")

    atyp = packet[3]
    offset = 4
    if atyp == 0x01:
        host = socket.inet_ntoa(packet[offset : offset + 4])
        offset += 4
    elif atyp == 0x04:
        host = socket.inet_ntop(socket.AF_INET6, packet[offset : offset + 16])
        offset += 16
    else:
        raise RuntimeError(f"unsupported udp atyp {atyp}")
    port = struct.unpack("!H", packet[offset : offset + 2])[0]
    offset += 2
    return host, port, packet[offset:]


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


def run_tcp_half_close_case(socks_host, socks_port, target_host, target_port, payload, expected_reply):
    sock = perform_socks_connect(socks_host, socks_port, target_host, target_port)
    try:
        sock.sendall(payload)
        sock.shutdown(socket.SHUT_WR)
        reply = recv_exact(sock, len(expected_reply))
        if reply != expected_reply:
            raise RuntimeError(f"unexpected half-close reply {reply!r}")
    finally:
        sock.close()


def run_idle_timeout_case(socks_host, socks_port, target_host, target_port, read_timeout):
    sock = perform_socks_connect(socks_host, socks_port, target_host, target_port)
    try:
        sock.settimeout(read_timeout)
        data = sock.recv(1)
        if data:
            raise RuntimeError(f"unexpected idle-timeout payload {data!r}")
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

        request = encode_socks_udp_header(target_host, target_port) + payload
        udp_sock.sendto(request, (relay_host, relay_port))
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


class EofReplyTcpServer:
    def __init__(self, reply_payload):
        self.reply_payload = reply_payload
        self.received = b""
        self.saw_eof = False
        self.error = None
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(1)
        self.host, self.port = self.server.getsockname()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def close(self):
        try:
            self.server.close()
        except OSError:
            pass

    def join(self):
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise RuntimeError("eof reply tcp server did not exit")
        if self.error is not None:
            raise self.error

    def _serve(self):
        try:
            self.server.settimeout(10)
            conn, _peer = self.server.accept()
            with conn:
                conn.settimeout(10)
                chunks = []
                while True:
                    data = conn.recv(4096)
                    if not data:
                        self.saw_eof = True
                        break
                    chunks.append(data)
                self.received = b"".join(chunks)
                conn.sendall(self.reply_payload)
        except Exception as exc:
            self.error = exc
        finally:
            self.close()


class IdleTcpServer:
    def __init__(self):
        self.error = None
        self.saw_eof = False
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(1)
        self.host, self.port = self.server.getsockname()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def close(self):
        try:
            self.server.close()
        except OSError:
            pass

    def join(self):
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise RuntimeError("idle tcp server did not exit")
        if self.error is not None:
            raise self.error

    def _serve(self):
        try:
            self.server.settimeout(10)
            conn, _peer = self.server.accept()
            with conn:
                conn.settimeout(10)
                while True:
                    data = conn.recv(4096)
                    if not data:
                        self.saw_eof = True
                        break
        except Exception as exc:
            self.error = exc
        finally:
            self.close()


class FakeUpstreamSocksServer:
    def __init__(self, expected_sessions):
        self.expected_sessions = expected_sessions
        self.error = None
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(expected_sessions)
        self.tcp_host, self.tcp_port = self.server.getsockname()
        self.udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_server.bind(("127.0.0.1", 0))
        self.udp_host, self.udp_port = self.udp_server.getsockname()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def close(self):
        for sock in (self.server, self.udp_server):
            try:
                sock.close()
            except OSError:
                pass

    def join(self):
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise RuntimeError("fake upstream socks server did not exit")
        if self.error is not None:
            raise self.error

    def _serve(self):
        try:
            self.server.settimeout(10)
            for _ in range(self.expected_sessions):
                conn, _peer = self.server.accept()
                with conn:
                    conn.settimeout(10)
                    greeting = recv_exact(conn, 3)
                    if greeting != b"\x05\x01\x00":
                        raise RuntimeError(f"unexpected upstream greeting {greeting!r}")
                    conn.sendall(b"\x05\x00")

                    version, command, _rsv, atyp = recv_exact(conn, 4)
                    if version != 0x05:
                        raise RuntimeError(f"unexpected socks version {version}")
                    target_host, target_port = self._read_target(conn, atyp)
                    if command == 0x01:
                        self._handle_connect(conn, target_host, target_port)
                    elif command == 0x03:
                        self._handle_udp_associate(conn)
                    else:
                        raise RuntimeError(f"unsupported socks command {command}")
        except Exception as exc:
            self.error = exc
        finally:
            self.close()

    def _read_target(self, conn, atyp):
        if atyp == 0x01:
            host = socket.inet_ntoa(recv_exact(conn, 4))
        elif atyp == 0x03:
            host_len = recv_exact(conn, 1)[0]
            host = recv_exact(conn, host_len).decode("utf-8")
        elif atyp == 0x04:
            host = socket.inet_ntop(socket.AF_INET6, recv_exact(conn, 16))
        else:
            raise RuntimeError(f"unsupported socks atyp {atyp}")
        port = struct.unpack("!H", recv_exact(conn, 2))[0]
        return host, port

    def _handle_connect(self, conn, target_host, target_port):
        upstream = socket.create_connection((target_host, target_port), timeout=5)
        upstream.settimeout(10)
        bind_host, bind_port = upstream.getsockname()
        reply = bytearray(b"\x05\x00\x00\x01")
        reply.extend(socket.inet_aton(bind_host))
        reply.extend(struct.pack("!H", bind_port))
        conn.sendall(reply)

        relay_errors = []

        def pipe(src, dst):
            try:
                while True:
                    data = src.recv(65535)
                    if not data:
                        try:
                            dst.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        return
                    dst.sendall(data)
            except OSError as exc:
                if exc.errno not in (9, 32, 104):
                    relay_errors.append(str(exc))
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        left = threading.Thread(target=pipe, args=(conn, upstream), daemon=True)
        right = threading.Thread(target=pipe, args=(upstream, conn), daemon=True)
        left.start()
        right.start()
        left.join(timeout=10)
        right.join(timeout=10)
        upstream.close()
        if relay_errors:
            raise RuntimeError(f"tcp relay failed: {relay_errors[0]}")

    def _handle_udp_associate(self, conn):
        reply = bytearray(b"\x05\x00\x00\x01")
        reply.extend(socket.inet_aton(self.udp_host))
        reply.extend(struct.pack("!H", self.udp_port))
        conn.sendall(reply)

        packet, sender = self.udp_server.recvfrom(65535)
        target_host, target_port, payload = decode_socks_udp_packet(packet)
        upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream.settimeout(5)
        try:
            upstream.sendto(payload, (target_host, target_port))
            response_payload, _peer = upstream.recvfrom(65535)
        finally:
            upstream.close()

        response = encode_socks_udp_header(target_host, target_port) + response_payload
        self.udp_server.sendto(response, sender)

        conn.settimeout(2)
        try:
            while conn.recv(64):
                pass
        except (socket.timeout, OSError):
            pass


def main():
    parser = argparse.ArgumentParser(description="Cross-outbound consistency regression")
    parser.add_argument("--binary", default=str(pathlib.Path("build") / "socks"), help="path to the socks binary")
    parser.add_argument("--keep-artifacts", action="store_true")
    args = parser.parse_args()

    repo_root = pathlib.Path(__file__).resolve().parents[1]
    binary = pathlib.Path(args.binary)
    if not binary.is_absolute():
        binary = (repo_root / binary).resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError(f"binary not found: {binary}")

    for command_name in ("python3",):
        if shutil.which(command_name) is None:
            raise RuntimeError(f"missing dependency: {command_name}")

    temp_root = pathlib.Path(tempfile.mkdtemp(prefix=".tmp-outbound-consistency.", dir=repo_root))
    helper_processes = []
    fake_socks_server = None
    try:
        runtime_env = build_runtime_env(binary)
        direct_port = allocate_tcp_port()
        socks_port = allocate_tcp_port()
        reality_port = allocate_tcp_port()
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

        fake_socks_server = FakeUpstreamSocksServer(expected_sessions=3)
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
            "workers": 1,
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
            "workers": 1,
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
                    "tag": "direct-in",
                    "settings": {
                        "host": "127.0.0.1",
                        "port": direct_port,
                        "auth": False,
                    },
                },
                {
                    "type": "socks",
                    "tag": "socks-out-in",
                    "settings": {
                        "host": "127.0.0.1",
                        "port": socks_port,
                        "auth": False,
                    },
                },
                {
                    "type": "socks",
                    "tag": "reality-out-in",
                    "settings": {
                        "host": "127.0.0.1",
                        "port": reality_port,
                        "auth": False,
                    },
                },
            ],
            "outbounds": [
                {
                    "type": "direct",
                    "tag": "direct",
                },
                {
                    "type": "socks",
                    "tag": "socks-out",
                    "settings": {
                        "host": fake_socks_server.tcp_host,
                        "port": fake_socks_server.tcp_port,
                        "auth": False,
                    },
                },
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
                    "type": "block",
                    "tag": "block",
                },
            ],
            "routing": [
                {
                    "type": "inbound",
                    "values": ["direct-in"],
                    "out": "direct",
                },
                {
                    "type": "inbound",
                    "values": ["socks-out-in"],
                    "out": "socks-out",
                },
                {
                    "type": "inbound",
                    "values": ["reality-out-in"],
                    "out": "reality-out",
                },
            ],
        }

        save_json(temp_root / "server.json", server_cfg)
        save_json(temp_root / "client.json", client_cfg)

        server_process = start_process([str(binary), "-c", str(temp_root / "server.json")], str(temp_root / "server.stdout.log"), extra_env=runtime_env)
        client_process = start_process([str(binary), "-c", str(temp_root / "client.json")], str(temp_root / "client.stdout.log"), extra_env=runtime_env)
        helper_processes.extend([server_process, client_process])

        wait_for_log_text(server_log, f"listen 127.0.0.1:{reality_server_port} reality inbound listening", 20, "reality server log")
        for port in (direct_port, socks_port, reality_port):
            wait_for_log_text(client_log, f":{port} socks listening", 20, f"client socks port {port}")
            wait_for_port("127.0.0.1", port, 20, f"socks port {port}", [client_process])
        wait_for_port("127.0.0.1", web_port, 20, "client trace web", [client_process])

        socks_ports = {
            "direct": direct_port,
            "socks-out": socks_port,
            "reality-out": reality_port,
        }

        half_close_ports = {}
        for label, socks_listen_port in socks_ports.items():
            server = EofReplyTcpServer(f"{label}-half-close-ok".encode("utf-8"))
            half_close_ports[label] = server.port
            run_tcp_half_close_case(
                "127.0.0.1",
                socks_listen_port,
                server.host,
                server.port,
                f"{label}-half-close-body".encode("utf-8"),
                f"{label}-half-close-ok".encode("utf-8"),
            )
            server.join()
            if not server.saw_eof:
                raise RuntimeError(f"{label} backend did not observe eof")
            if server.received != f"{label}-half-close-body".encode("utf-8"):
                raise RuntimeError(f"{label} backend payload mismatch {server.received!r}")

        large_payload = bytes((index % 251 for index in range(65497)))
        for label, socks_listen_port in socks_ports.items():
            run_udp_echo_case("127.0.0.1", socks_listen_port, "127.0.0.1", udp_echo_port, large_payload)

        idle_ports = {}
        for label, socks_listen_port in socks_ports.items():
            idle_server = IdleTcpServer()
            idle_ports[label] = idle_server.port
            run_idle_timeout_case("127.0.0.1", socks_listen_port, idle_server.host, idle_server.port, 8.0)
            idle_server.join()
            if not idle_server.saw_eof:
                raise RuntimeError(f"{label} idle backend did not observe eof")

        deadline = time.time() + 5.0
        close_events = []
        while time.time() < deadline:
            payload = fetch_json(f"http://127.0.0.1:{web_port}/api/traces/events?stage=session_close&limit=200")
            close_events = payload.get("items") or payload.get("events") or []
            idle_matched = {
                event.get("target_port"): event
                for event in close_events
                if event.get("inbound_type") == "socks" and event.get("extra", {}).get("close_reason") == "idle_timeout"
            }
            completed_matched = {
                event.get("target_port"): event
                for event in close_events
                if event.get("inbound_type") == "socks" and event.get("extra", {}).get("close_reason") == "completed"
            }
            if all(idle_ports[label] in idle_matched for label in idle_ports) and all(
                half_close_ports[label] in completed_matched for label in half_close_ports
            ):
                break
            time.sleep(0.1)
        else:
            raise RuntimeError(f"missing close events: {close_events}")

        for label, target_port in half_close_ports.items():
            matched_event = next(
                (
                    event
                    for event in close_events
                    if event.get("target_port") == target_port
                    and event.get("inbound_type") == "socks"
                    and event.get("extra", {}).get("close_reason") == "completed"
                ),
                None,
            )
            if matched_event is None:
                raise RuntimeError(f"missing completed close event for {label} target {target_port}")
            if matched_event.get("route_type") != label:
                raise RuntimeError(f"unexpected completed route type for {label}: {matched_event}")

        for label, target_port in idle_ports.items():
            matched_event = next(
                (
                    event
                    for event in close_events
                    if event.get("target_port") == target_port
                    and event.get("inbound_type") == "socks"
                    and event.get("extra", {}).get("close_reason") == "idle_timeout"
                ),
                None,
            )
            if matched_event is None:
                raise RuntimeError(f"missing idle timeout close event for {label} target {target_port}")
            if matched_event.get("route_type") != label:
                raise RuntimeError(f"unexpected route type for {label}: {matched_event}")
            duration_ms = int(matched_event.get("extra", {}).get("duration_ms", "0"))
            if duration_ms < 3000:
                raise RuntimeError(f"idle timeout duration too short for {label}: {matched_event}")

        fake_socks_server.join()
        print("tcp_half_close_matrix ok")
        print("udp_large_payload_matrix ok")
        print("idle_timeout_matrix ok")
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
        if args.keep_artifacts:
            print(f"artifacts kept at {temp_root}", file=sys.stderr)
        else:
            shutil.rmtree(temp_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
