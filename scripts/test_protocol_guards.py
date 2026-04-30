#!/usr/bin/env python3

import argparse
import ipaddress
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

from testlib import allocate_tcp_port, allocate_udp_port, build_runtime_env, save_json, start_process, tail_file, wait_for_log_text


def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError(f"socket closed early while reading {size} bytes")
        data.extend(chunk)
    return bytes(data)


def recv_socks_reply(sock):
    header = recv_exact(sock, 4)
    atyp = header[3]
    if atyp == 0x01:
        recv_exact(sock, 6)
    elif atyp == 0x03:
        host_len = recv_exact(sock, 1)[0]
        recv_exact(sock, host_len + 2)
    elif atyp == 0x04:
        recv_exact(sock, 18)
    else:
        raise RuntimeError(f"unexpected socks atyp {atyp}")
    return header[1]


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
        raise RuntimeError(f"unexpected socks atyp {atyp}")
    port = int.from_bytes(recv_exact(sock, 2), "big")
    return host, port


def run_socks_outbound_auth_guard_case(binary, runtime_env, temp_root):
    listen_host = "127.0.0.1"
    listen_port = allocate_tcp_port()
    upstream_port = allocate_tcp_port()
    log_path = temp_root / "socks-outbound-auth-guard.log"
    run_log = temp_root / "socks-outbound-auth-guard.stdout.log"

    cfg = {
        "workers": 1,
        "log": {
            "level": "debug",
            "file": str(log_path),
        },
        "timeout": {
            "read": 5,
            "write": 5,
            "connect": 5,
            "idle": 5,
        },
        "inbounds": [
            {
                "type": "socks",
                "tag": "socks-in",
                "settings": {
                    "host": listen_host,
                    "port": listen_port,
                    "auth": False,
                },
            }
        ],
        "outbounds": [
            {
                "type": "socks",
                "tag": "socks-out",
                "settings": {
                    "host": listen_host,
                    "port": upstream_port,
                    "auth": False,
                    "username": "secret-user",
                    "password": "secret-pass",
                },
            }
        ],
        "routing": [
            {
                "type": "inbound",
                "values": ["socks-in"],
                "out": "socks-out",
            }
        ],
    }

    config_path = temp_root / "socks-outbound-auth-guard.json"
    save_json(config_path, cfg)

    server_ready = threading.Event()
    server_state = {"greeting": b"", "extra_data": b""}
    server_error = []

    def fake_upstream_server():
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((listen_host, upstream_port))
        server.listen(1)
        server_ready.set()
        try:
            conn, _ = server.accept()
            with conn:
                conn.settimeout(2)
                server_state["greeting"] = recv_exact(conn, 3)
                conn.sendall(b"\x05\x02")
                try:
                    server_state["extra_data"] = conn.recv(256)
                except socket.timeout:
                    server_state["extra_data"] = b""
        except Exception as exc:
            server_error.append(str(exc))
        finally:
            server.close()

    server_thread = threading.Thread(target=fake_upstream_server, daemon=True)
    server_thread.start()
    if not server_ready.wait(timeout=5):
        raise RuntimeError("fake upstream socks server did not start")

    process = start_process([str(binary), "-c", str(config_path)], str(run_log), extra_env=runtime_env)
    try:
        wait_for_log_text(log_path, f"listen {listen_host}:{listen_port} socks listening", 20, "socks outbound auth guard log")

        client = socket.create_connection((listen_host, listen_port), timeout=5)
        with client:
            client.settimeout(5)
            client.sendall(b"\x05\x01\x00")
            method_reply = recv_exact(client, 2)
            if method_reply != b"\x05\x00":
                raise RuntimeError(f"unexpected inbound method reply {method_reply!r}")

            client.sendall(b"\x05\x01\x00\x03\x0bexample.com\x00\x50")
            connect_reply = recv_exact(client, 10)
            if connect_reply[1] == 0x00:
                raise RuntimeError(f"unexpected outbound connect success {connect_reply!r}")
    finally:
        process.terminate()

    server_thread.join(timeout=5)
    if server_thread.is_alive():
        raise RuntimeError("fake upstream socks server did not exit")
    if server_error:
        raise RuntimeError(f"fake upstream socks server failed: {server_error[0]}")
    if server_state["greeting"] != b"\x05\x01\x00":
        raise RuntimeError(f"unexpected outbound greeting {server_state['greeting']!r}")
    if server_state["extra_data"]:
        raise RuntimeError(f"unexpected outbound auth payload leaked {server_state['extra_data']!r}")


def run_socks_outbound_required_auth_reply_guard_case(binary, runtime_env, temp_root):
    listen_host = "127.0.0.1"
    listen_port = allocate_tcp_port()
    upstream_port = allocate_tcp_port()
    log_path = temp_root / "socks-outbound-required-auth-reply-guard.log"
    run_log = temp_root / "socks-outbound-required-auth-reply-guard.stdout.log"

    cfg = {
        "workers": 1,
        "log": {
            "level": "debug",
            "file": str(log_path),
        },
        "timeout": {
            "read": 5,
            "write": 5,
            "connect": 5,
            "idle": 5,
        },
        "inbounds": [
            {
                "type": "socks",
                "tag": "socks-in",
                "settings": {
                    "host": listen_host,
                    "port": listen_port,
                    "auth": False,
                },
            }
        ],
        "outbounds": [
            {
                "type": "socks",
                "tag": "socks-out",
                "settings": {
                    "host": listen_host,
                    "port": upstream_port,
                    "auth": True,
                    "username": "secret-user",
                    "password": "secret-pass",
                },
            }
        ],
        "routing": [
            {
                "type": "inbound",
                "values": ["socks-in"],
                "out": "socks-out",
            }
        ],
    }

    config_path = temp_root / "socks-outbound-required-auth-reply-guard.json"
    save_json(config_path, cfg)

    server_ready = threading.Event()
    server_state = {"greeting": b"", "extra_data": b""}
    server_error = []

    def fake_upstream_server():
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((listen_host, upstream_port))
        server.listen(1)
        server_ready.set()
        try:
            conn, _ = server.accept()
            with conn:
                conn.settimeout(2)
                server_state["greeting"] = recv_exact(conn, 3)
                conn.sendall(b"\x05\x00")
                try:
                    server_state["extra_data"] = conn.recv(256)
                except socket.timeout:
                    server_state["extra_data"] = b""
        except Exception as exc:
            server_error.append(str(exc))
        finally:
            server.close()

    server_thread = threading.Thread(target=fake_upstream_server, daemon=True)
    server_thread.start()
    if not server_ready.wait(timeout=5):
        raise RuntimeError("fake upstream socks required auth reply guard server did not start")

    process = start_process([str(binary), "-c", str(config_path)], str(run_log), extra_env=runtime_env)
    try:
        wait_for_log_text(log_path, f"listen {listen_host}:{listen_port} socks listening", 20, "socks outbound required auth reply guard log")

        client = socket.create_connection((listen_host, listen_port), timeout=5)
        with client:
            client.settimeout(5)
            client.sendall(b"\x05\x01\x00")
            method_reply = recv_exact(client, 2)
            if method_reply != b"\x05\x00":
                raise RuntimeError(f"unexpected inbound method reply {method_reply!r}")

            client.sendall(b"\x05\x01\x00\x03\x0bexample.com\x00\x50")
            connect_reply = recv_exact(client, 10)
            if connect_reply[1] == 0x00:
                raise RuntimeError(f"unexpected outbound connect success {connect_reply!r}")
    finally:
        process.terminate()

    server_thread.join(timeout=5)
    if server_thread.is_alive():
        raise RuntimeError("fake upstream socks required auth reply guard server did not exit")
    if server_error:
        raise RuntimeError(f"fake upstream socks required auth reply guard server failed: {server_error[0]}")
    if server_state["greeting"] != b"\x05\x01\x02":
        raise RuntimeError(f"unexpected outbound greeting {server_state['greeting']!r}")
    if server_state["extra_data"]:
        raise RuntimeError(f"unexpected outbound auth payload leaked {server_state['extra_data']!r}")


def run_socks_udp_outbound_reply_guard_case(binary, runtime_env, temp_root):
    repo_root = pathlib.Path(__file__).resolve().parents[1]
    listen_host = "127.0.0.1"
    listen_port = allocate_tcp_port()
    upstream_tcp_port = allocate_tcp_port()
    upstream_udp_port = allocate_tcp_port()
    log_path = temp_root / "socks-udp-outbound-reply-guard.log"
    run_log = temp_root / "socks-udp-outbound-reply-guard.stdout.log"

    cfg = {
        "workers": 1,
        "log": {
            "level": "debug",
            "file": str(log_path),
        },
        "timeout": {
            "read": 5,
            "write": 5,
            "connect": 5,
            "idle": 5,
        },
        "inbounds": [
            {
                "type": "socks",
                "tag": "socks-in",
                "settings": {
                    "host": listen_host,
                    "port": listen_port,
                    "auth": False,
                },
            }
        ],
        "outbounds": [
            {
                "type": "socks",
                "tag": "socks-out",
                "settings": {
                    "host": listen_host,
                    "port": upstream_tcp_port,
                    "auth": False,
                },
            }
        ],
        "routing": [
            {
                "type": "inbound",
                "values": ["socks-in"],
                "out": "socks-out",
            }
        ],
    }

    config_path = temp_root / "socks-udp-outbound-reply-guard.json"
    save_json(config_path, cfg)

    server_ready = threading.Event()
    server_error = []
    server_state = {"udp_request": b""}

    def fake_upstream_server():
        tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rogue_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            tcp_server.bind((listen_host, upstream_tcp_port))
            tcp_server.listen(1)
            udp_server.bind((listen_host, upstream_udp_port))
            rogue_udp.bind((listen_host, 0))
            server_ready.set()

            conn, _ = tcp_server.accept()
            with conn:
                conn.settimeout(5)
                greeting = recv_exact(conn, 3)
                if greeting != b"\x05\x01\x00":
                    raise RuntimeError(f"unexpected upstream greeting {greeting!r}")
                conn.sendall(b"\x05\x00")

                associate_request = recv_exact(conn, 10)
                if associate_request != b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00":
                    raise RuntimeError(f"unexpected udp associate request {associate_request!r}")

                associate_reply = bytearray(b"\x05\x00\x00\x01")
                associate_reply.extend(socket.inet_aton(listen_host))
                associate_reply.extend(upstream_udp_port.to_bytes(2, "big"))
                conn.sendall(associate_reply)

                udp_server.settimeout(5)
                request_packet, outbound_client = udp_server.recvfrom(65535)
                server_state["udp_request"] = request_packet

                rogue_udp.sendto(request_packet, outbound_client)
                time.sleep(0.05)

                fragmented_packet = bytearray(request_packet)
                fragmented_packet[2] = 0x01
                udp_server.sendto(fragmented_packet, outbound_client)
                time.sleep(0.05)

                udp_server.sendto(request_packet, outbound_client)
                time.sleep(0.2)
        except Exception as exc:
            server_error.append(str(exc))
        finally:
            rogue_udp.close()
            udp_server.close()
            tcp_server.close()

    server_thread = threading.Thread(target=fake_upstream_server, daemon=True)
    server_thread.start()
    if not server_ready.wait(timeout=5):
        raise RuntimeError("fake upstream socks udp server did not start")

    process = start_process([str(binary), "-c", str(config_path)], str(run_log), extra_env=runtime_env)
    try:
        wait_for_log_text(log_path, f"listen {listen_host}:{listen_port} socks listening", 20, "socks udp outbound reply guard log")

        udp_result = subprocess.run(
            [
                sys.executable,
                str(repo_root / "scripts/socks5_udp_client.py"),
                "--socks-host",
                listen_host,
                "--socks-port",
                str(listen_port),
                "--target-host",
                "127.0.0.1",
                "--target-port",
                "53530",
                "--payload",
                "udp-guard",
            ],
            env=runtime_env,
            text=True,
            capture_output=True,
            check=False,
        )
        if udp_result.returncode != 0:
            raise RuntimeError(f"udp client failed rc={udp_result.returncode} stdout={udp_result.stdout} stderr={udp_result.stderr}")
        if udp_result.stdout.strip() != "udp-guard":
            raise RuntimeError(f"unexpected udp guard response {udp_result.stdout!r}")

        wait_for_log_text(log_path, "ignore unexpected sender", 5, "socks udp outbound reply guard log")
        wait_for_log_text(log_path, "ignore fragmented packet", 5, "socks udp outbound reply guard log")
    finally:
        process.terminate()

    server_thread.join(timeout=5)
    if server_thread.is_alive():
        raise RuntimeError("fake upstream socks udp server did not exit")
    if server_error:
        raise RuntimeError(f"fake upstream socks udp server failed: {server_error[0]}")
    if not server_state["udp_request"]:
        raise RuntimeError("missing udp request received by fake upstream socks server")


def run_socks_udp_fragmented_client_guard_case(binary, runtime_env, temp_root):
    listen_host = "127.0.0.1"
    listen_port = allocate_tcp_port()
    target_port = allocate_udp_port()
    log_path = temp_root / "socks-udp-fragmented-client-guard.log"
    run_log = temp_root / "socks-udp-fragmented-client-guard.stdout.log"

    cfg = {
        "workers": 1,
        "log": {
            "level": "debug",
            "file": str(log_path),
        },
        "timeout": {
            "read": 5,
            "write": 5,
            "connect": 5,
            "idle": 5,
        },
        "inbounds": [
            {
                "type": "socks",
                "tag": "socks-in",
                "settings": {
                    "host": listen_host,
                    "port": listen_port,
                    "auth": False,
                },
            }
        ],
        "outbounds": [
            {
                "type": "direct",
                "tag": "direct",
            }
        ],
        "routing": [
            {
                "type": "inbound",
                "values": ["socks-in"],
                "out": "direct",
            }
        ],
    }

    config_path = temp_root / "socks-udp-fragmented-client-guard.json"
    save_json(config_path, cfg)

    echo_ready = threading.Event()
    echo_error = []
    echo_state = {"requests": []}

    def udp_echo_server():
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind((listen_host, target_port))
        server.settimeout(5)
        echo_ready.set()
        try:
            while len(echo_state["requests"]) < 1:
                payload, peer = server.recvfrom(65535)
                echo_state["requests"].append(payload)
                server.sendto(payload, peer)
        except Exception as exc:
            echo_error.append(str(exc))
        finally:
            server.close()

    echo_thread = threading.Thread(target=udp_echo_server, daemon=True)
    echo_thread.start()
    if not echo_ready.wait(timeout=5):
        raise RuntimeError("udp echo guard server did not start")

    process = start_process([str(binary), "-c", str(config_path)], str(run_log), extra_env=runtime_env)
    try:
        wait_for_log_text(log_path, f"listen {listen_host}:{listen_port} socks listening", 20, "socks udp fragmented client guard log")

        tcp_sock = socket.create_connection((listen_host, listen_port), timeout=5)
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            tcp_sock.settimeout(5)
            udp_sock.settimeout(0.5)
            tcp_sock.sendall(b"\x05\x01\x00")
            method_reply = recv_exact(tcp_sock, 2)
            if method_reply != b"\x05\x00":
                raise RuntimeError(f"unexpected inbound method reply {method_reply!r}")

            tcp_sock.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
            version, rep, _rsv = recv_exact(tcp_sock, 3)
            if version != 0x05 or rep != 0x00:
                raise RuntimeError(f"udp associate failed version={version} rep={rep}")
            relay_host, relay_port = parse_socks_address(tcp_sock)

            fragmented_packet = bytearray(b"\x00\x00\x01\x01")
            fragmented_packet.extend(socket.inet_aton(listen_host))
            fragmented_packet.extend(target_port.to_bytes(2, "big"))
            fragmented_packet.extend(b"fragmented-drop")
            udp_sock.sendto(fragmented_packet, (relay_host, relay_port))
            try:
                reply, _peer = udp_sock.recvfrom(65535)
                raise RuntimeError(f"unexpected fragmented udp reply {reply!r}")
            except socket.timeout:
                pass

            empty_host_packet = bytearray(b"\x00\x00\x00\x03\x00")
            empty_host_packet.extend(target_port.to_bytes(2, "big"))
            empty_host_packet.extend(b"empty-host-drop")
            udp_sock.sendto(empty_host_packet, (relay_host, relay_port))
            try:
                reply, _peer = udp_sock.recvfrom(65535)
                raise RuntimeError(f"unexpected empty-host udp reply {reply!r}")
            except socket.timeout:
                pass

            zero_port_packet = bytearray(b"\x00\x00\x00\x01")
            zero_port_packet.extend(socket.inet_aton(listen_host))
            zero_port_packet.extend(b"\x00\x00")
            zero_port_packet.extend(b"zero-port-drop")
            udp_sock.sendto(zero_port_packet, (relay_host, relay_port))
            try:
                reply, _peer = udp_sock.recvfrom(65535)
                raise RuntimeError(f"unexpected zero-port udp reply {reply!r}")
            except socket.timeout:
                pass

            valid_packet = bytearray(b"\x00\x00\x00\x01")
            valid_packet.extend(socket.inet_aton(listen_host))
            valid_packet.extend(target_port.to_bytes(2, "big"))
            valid_packet.extend(b"valid-after-frag")
            udp_sock.sendto(valid_packet, (relay_host, relay_port))
            reply, _peer = udp_sock.recvfrom(65535)
            if not reply.endswith(b"valid-after-frag"):
                raise RuntimeError(f"unexpected valid udp reply {reply!r}")
        finally:
            udp_sock.close()
            tcp_sock.close()

        wait_for_log_text(log_path, "received fragmented udp packet frag 1", 5, "socks udp fragmented client guard log")
        wait_for_log_text(log_path, "received invalid udp packet", 5, "socks udp fragmented client guard log")
        wait_for_log_text(log_path, "received udp packet with invalid target port 0", 5, "socks udp fragmented client guard log")
    finally:
        process.terminate()

    echo_thread.join(timeout=5)
    if echo_thread.is_alive():
        raise RuntimeError("udp echo guard server did not exit")
    if echo_error:
        raise RuntimeError(f"udp echo guard server failed: {echo_error[0]}")
    if echo_state["requests"] != [b"valid-after-frag"]:
        raise RuntimeError(f"unexpected udp echo requests {echo_state['requests']!r}")


def run_socks_udp_tcp_control_flood_guard_case(binary, runtime_env, temp_root):
    listen_host = "127.0.0.1"
    listen_port = allocate_tcp_port()
    target_port = allocate_udp_port()
    log_path = temp_root / "socks-udp-tcp-control-flood-guard.log"
    run_log = temp_root / "socks-udp-tcp-control-flood-guard.stdout.log"

    cfg = {
        "workers": 1,
        "log": {
            "level": "debug",
            "file": str(log_path),
        },
        "timeout": {
            "read": 5,
            "write": 5,
            "connect": 5,
            "idle": 5,
        },
        "inbounds": [
            {
                "type": "socks",
                "tag": "socks-in",
                "settings": {
                    "host": listen_host,
                    "port": listen_port,
                    "auth": False,
                },
            }
        ],
        "outbounds": [
            {
                "type": "direct",
                "tag": "direct",
            }
        ],
        "routing": [
            {
                "type": "inbound",
                "values": ["socks-in"],
                "out": "direct",
            }
        ],
    }

    config_path = temp_root / "socks-udp-tcp-control-flood-guard.json"
    save_json(config_path, cfg)

    echo_ready = threading.Event()
    echo_error = []
    echo_state = {"requests": []}

    def udp_echo_server():
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind((listen_host, target_port))
        server.settimeout(5)
        echo_ready.set()
        try:
            while len(echo_state["requests"]) < 1:
                payload, peer = server.recvfrom(65535)
                echo_state["requests"].append(payload)
                server.sendto(payload, peer)
        except Exception as exc:
            echo_error.append(str(exc))
        finally:
            server.close()

    echo_thread = threading.Thread(target=udp_echo_server, daemon=True)
    echo_thread.start()
    if not echo_ready.wait(timeout=5):
        raise RuntimeError("udp echo flood guard server did not start")

    process = start_process([str(binary), "-c", str(config_path)], str(run_log), extra_env=runtime_env)
    try:
        wait_for_log_text(log_path, f"listen {listen_host}:{listen_port} socks listening", 20, "socks udp tcp control flood guard log")

        tcp_sock = socket.create_connection((listen_host, listen_port), timeout=5)
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            tcp_sock.settimeout(5)
            udp_sock.settimeout(0.5)
            tcp_sock.sendall(b"\x05\x01\x00")
            method_reply = recv_exact(tcp_sock, 2)
            if method_reply != b"\x05\x00":
                raise RuntimeError(f"unexpected inbound method reply {method_reply!r}")

            tcp_sock.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
            version, rep, _rsv = recv_exact(tcp_sock, 3)
            if version != 0x05 or rep != 0x00:
                raise RuntimeError(f"udp associate failed version={version} rep={rep}")
            relay_host, relay_port = parse_socks_address(tcp_sock)

            request = bytearray(b"\x00\x00\x00\x01")
            request.extend(socket.inet_aton(listen_host))
            request.extend(target_port.to_bytes(2, "big"))
            request.extend(b"before-flood")
            udp_sock.sendto(request, (relay_host, relay_port))
            reply, _peer = udp_sock.recvfrom(65535)
            if not reply.endswith(b"before-flood"):
                raise RuntimeError(f"unexpected pre-flood udp reply {reply!r}")

            tcp_sock.sendall(b"x" * 5000)
            wait_for_log_text(log_path, "tcp control channel flooded", 5, "socks udp tcp control flood guard log")

            request = bytearray(b"\x00\x00\x00\x01")
            request.extend(socket.inet_aton(listen_host))
            request.extend(target_port.to_bytes(2, "big"))
            request.extend(b"after-flood")
            udp_sock.sendto(request, (relay_host, relay_port))
            try:
                reply, _peer = udp_sock.recvfrom(65535)
                raise RuntimeError(f"unexpected post-flood udp reply {reply!r}")
            except (socket.timeout, ConnectionRefusedError):
                pass
        finally:
            udp_sock.close()
            tcp_sock.close()
    finally:
        process.terminate()

    echo_thread.join(timeout=5)
    if echo_thread.is_alive():
        raise RuntimeError("udp echo flood guard server did not exit")
    if echo_error:
        raise RuntimeError(f"udp echo flood guard server failed: {echo_error[0]}")
    if echo_state["requests"] != [b"before-flood"]:
        raise RuntimeError(f"unexpected udp flood guard requests {echo_state['requests']!r}")


def run_ipv4_mapped_tcp_route_guard_case(binary, runtime_env, temp_root):
    listen_host = "127.0.0.1"
    listen_port = allocate_tcp_port()
    upstream_port = allocate_tcp_port()
    log_path = temp_root / "ipv4-mapped-tcp-route-guard.log"
    run_log = temp_root / "ipv4-mapped-tcp-route-guard.stdout.log"

    cfg = {
        "workers": 1,
        "log": {
            "level": "debug",
            "file": str(log_path),
        },
        "timeout": {
            "read": 5,
            "write": 5,
            "connect": 5,
            "idle": 5,
        },
        "inbounds": [
            {
                "type": "socks",
                "tag": "socks-in",
                "settings": {
                    "host": listen_host,
                    "port": listen_port,
                    "auth": False,
                },
            }
        ],
        "outbounds": [
            {
                "type": "socks",
                "tag": "socks-out",
                "settings": {
                    "host": listen_host,
                    "port": upstream_port,
                    "auth": False,
                },
            },
            {
                "type": "block",
                "tag": "block",
            },
        ],
        "routing": [
            {
                "type": "ip",
                "values": ["127.0.0.1/32"],
                "out": "block",
            },
            {
                "type": "inbound",
                "values": ["socks-in"],
                "out": "socks-out",
            },
        ],
    }

    config_path = temp_root / "ipv4-mapped-tcp-route-guard.json"
    save_json(config_path, cfg)

    server_ready = threading.Event()
    server_error = []
    server_state = {"accepted": False, "greeting": b"", "connect_request": b""}

    def fake_upstream_server():
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((listen_host, upstream_port))
        server.listen(1)
        server.settimeout(2)
        server_ready.set()
        try:
            conn, _ = server.accept()
            server_state["accepted"] = True
            with conn:
                conn.settimeout(2)
                server_state["greeting"] = recv_exact(conn, 3)
                conn.sendall(b"\x05\x00")
                server_state["connect_request"] = recv_exact(conn, 10)
                reply = bytearray(b"\x05\x00\x00\x01")
                reply.extend(socket.inet_aton(listen_host))
                reply.extend((1080).to_bytes(2, "big"))
                conn.sendall(reply)
        except socket.timeout:
            pass
        except Exception as exc:
            server_error.append(str(exc))
        finally:
            server.close()

    server_thread = threading.Thread(target=fake_upstream_server, daemon=True)
    server_thread.start()
    if not server_ready.wait(timeout=5):
        raise RuntimeError("fake upstream ipv4 mapped route guard server did not start")

    process = start_process([str(binary), "-c", str(config_path)], str(run_log), extra_env=runtime_env)
    try:
        wait_for_log_text(log_path, f"listen {listen_host}:{listen_port} socks listening", 20, "ipv4 mapped route guard log")

        client = socket.create_connection((listen_host, listen_port), timeout=5)
        with client:
            client.settimeout(5)
            client.sendall(b"\x05\x01\x00")
            method_reply = recv_exact(client, 2)
            if method_reply != b"\x05\x00":
                raise RuntimeError(f"unexpected inbound method reply {method_reply!r}")

            request = bytearray(b"\x05\x01\x00\x04")
            request.extend(ipaddress.ip_address("::ffff:127.0.0.1").packed)
            request.extend((80).to_bytes(2, "big"))
            client.sendall(request)
            rep = recv_socks_reply(client)
            if rep == 0x00:
                raise RuntimeError("unexpected tcp connect success for ipv4-mapped route guard case")
    finally:
        process.terminate()

    server_thread.join(timeout=5)
    if server_thread.is_alive():
        raise RuntimeError("fake upstream ipv4 mapped route guard server did not exit")
    if server_error:
        raise RuntimeError(f"fake upstream ipv4 mapped route guard server failed: {server_error[0]}")
    if server_state["accepted"]:
        raise RuntimeError(
            f"unexpected upstream socks contact greeting={server_state['greeting']!r} connect_request={server_state['connect_request']!r}"
        )


def main():
    parser = argparse.ArgumentParser(description="Protocol guard regression test")
    parser.add_argument("--binary", default=str(pathlib.Path("build") / "socks"), help="path to the socks binary")
    parser.add_argument("--keep-artifacts", action="store_true")
    args = parser.parse_args()

    repo_root = pathlib.Path(__file__).resolve().parents[1]
    binary = pathlib.Path(args.binary)
    if not binary.is_absolute():
        binary = (repo_root / binary).resolve()
    if not binary.is_file() or not binary.exists():
        raise RuntimeError(f"binary not found: {binary}")

    temp_root = pathlib.Path(tempfile.mkdtemp(prefix=".tmp-protocol-guards.", dir=repo_root))
    try:
        runtime_env = build_runtime_env(binary)
        run_socks_outbound_auth_guard_case(binary, runtime_env, temp_root)
        print("socks_outbound_auth_guard ok")
        run_socks_outbound_required_auth_reply_guard_case(binary, runtime_env, temp_root)
        print("socks_outbound_required_auth_reply_guard ok")
        run_ipv4_mapped_tcp_route_guard_case(binary, runtime_env, temp_root)
        print("ipv4_mapped_tcp_route_guard ok")
        run_socks_udp_outbound_reply_guard_case(binary, runtime_env, temp_root)
        print("socks_udp_outbound_reply_guard ok")
        run_socks_udp_fragmented_client_guard_case(binary, runtime_env, temp_root)
        print("socks_udp_fragmented_client_guard ok")
        run_socks_udp_tcp_control_flood_guard_case(binary, runtime_env, temp_root)
        print("socks_udp_tcp_control_flood_guard ok")
        return 0
    except Exception as exc:
        print(f"test failed {exc}", file=sys.stderr)
        for log_path in sorted(temp_root.glob("**/*.log")):
            print(f"===== {log_path.relative_to(temp_root)} =====", file=sys.stderr)
            print(tail_file(log_path), file=sys.stderr)
        raise
    finally:
        if args.keep_artifacts:
            print(f"artifacts kept at {temp_root}", file=sys.stderr)
        else:
            shutil.rmtree(temp_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
