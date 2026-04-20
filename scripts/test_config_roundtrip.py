#!/usr/bin/env python3

import argparse
import copy
import json
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

from testlib import allocate_tcp_port, build_runtime_env, parse_key_output, save_json, start_process, tail_file, wait_for_log_text


def assert_no_usage(case_name, output):
    if "Usage:" in output:
        raise RuntimeError(f"{case_name} unexpectedly printed usage: {output!r}")


def dump_default_config(binary, runtime_env):
    result = subprocess.run([str(binary), "config"], env=runtime_env, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"dump default config failed rc={result.returncode} stderr={result.stderr}")
    return json.loads(result.stdout)


def run_default_roundtrip(binary, runtime_env, temp_root):
    cfg = dump_default_config(binary, runtime_env)
    listen_host = cfg["inbounds"][0]["settings"]["host"]
    listen_port = allocate_tcp_port()
    log_path = temp_root / "roundtrip.log"
    run_log = temp_root / "roundtrip.stdout.log"
    cfg["log"]["file"] = str(log_path)
    cfg["inbounds"][0]["settings"]["port"] = listen_port

    config_path = temp_root / "roundtrip.json"
    save_json(config_path, cfg)

    process = start_process([str(binary), "-c", str(config_path)], str(run_log), extra_env=runtime_env)
    try:
        wait_for_log_text(log_path, f"listen {listen_host}:{listen_port} socks listening", 20, "roundtrip log")
    finally:
        process.terminate()


def run_marked_roundtrip(binary, runtime_env, temp_root):
    cfg = dump_default_config(binary, runtime_env)
    listen_host = cfg["inbounds"][0]["settings"]["host"]
    listen_port = allocate_tcp_port()
    log_path = temp_root / "marked-roundtrip.log"
    run_log = temp_root / "marked-roundtrip.stdout.log"
    cfg["log"]["file"] = str(log_path)
    cfg["inbounds"][0]["settings"]["port"] = listen_port
    cfg["inbounds"][0]["mark"] = 17
    cfg["outbounds"][0]["mark"] = 23

    config_path = temp_root / "marked-roundtrip.json"
    save_json(config_path, cfg)

    process = start_process([str(binary), "-c", str(config_path)], str(run_log), extra_env=runtime_env)
    try:
        wait_for_log_text(log_path, f"listen {listen_host}:{listen_port} socks listening", 20, "marked roundtrip log")
    finally:
        process.terminate()


def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError(f"socket closed early while reading {size} bytes")
        data.extend(chunk)
    return bytes(data)


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


def run_invalid_config_case(binary, runtime_env, temp_root):
    invalid_path = temp_root / "invalid.json"
    invalid_path.write_text("{\n", encoding="utf-8")

    result = subprocess.run([str(binary), "-c", str(invalid_path)], env=runtime_env, text=True, capture_output=True, check=False)
    if result.returncode == 0:
        raise RuntimeError("invalid config unexpectedly succeeded")

    combined = (result.stdout or "") + (result.stderr or "")
    if "json_parse" not in combined:
        raise RuntimeError(f"invalid config missing parse error output: {combined!r}")
    assert_no_usage("invalid_config", combined)


def run_invalid_reality_config_case(binary, runtime_env, temp_root, case_name, config_value, expected_error):
    config_path = temp_root / f"{case_name}.json"
    save_json(config_path, config_value)

    result = subprocess.run([str(binary), "-c", str(config_path)], env=runtime_env, text=True, capture_output=True, check=False)
    if result.returncode == 0:
        raise RuntimeError(f"{case_name} unexpectedly succeeded")

    combined = (result.stdout or "") + (result.stderr or "")
    if expected_error not in combined:
        raise RuntimeError(f"{case_name} missing error {expected_error!r} output={combined!r}")
    assert_no_usage(case_name, combined)


def run_invalid_config_value_case(binary, runtime_env, temp_root, case_name, config_value, expected_error):
    config_path = temp_root / f"{case_name}.json"
    save_json(config_path, config_value)

    result = subprocess.run([str(binary), "-c", str(config_path)], env=runtime_env, text=True, capture_output=True, check=False)
    if result.returncode == 0:
        raise RuntimeError(f"{case_name} unexpectedly succeeded")

    combined = (result.stdout or "") + (result.stderr or "")
    if expected_error not in combined:
        raise RuntimeError(f"{case_name} missing error {expected_error!r} output={combined!r}")
    assert_no_usage(case_name, combined)


def run_invalid_reality_config_cases(binary, runtime_env, temp_root):
    base_cfg = dump_default_config(binary, runtime_env)
    key_output = subprocess.run([str(binary), "x25519"], env=runtime_env, text=True, capture_output=True, check=False)
    if key_output.returncode != 0:
        raise RuntimeError(f"dump x25519 failed rc={key_output.returncode} stderr={key_output.stderr}")
    private_key, _ = parse_key_output(key_output.stdout)

    cases = []

    invalid_outbound_public_key = copy.deepcopy(base_cfg)
    invalid_outbound_public_key["outbounds"][0]["settings"]["public_key"] = "xyz"
    cases.append(
        (
            "invalid_outbound_public_key",
            invalid_outbound_public_key,
            "outbounds[0].settings.public_key hex length invalid",
        )
    )

    invalid_outbound_short_id = copy.deepcopy(base_cfg)
    invalid_outbound_short_id["outbounds"][0]["settings"]["short_id"] = "001"
    cases.append(
        (
            "invalid_outbound_short_id",
            invalid_outbound_short_id,
            "outbounds[0].settings.short_id hex length invalid",
        )
    )

    invalid_outbound_fingerprint = copy.deepcopy(base_cfg)
    invalid_outbound_fingerprint["outbounds"][0]["settings"]["fingerprint"] = "not-real"
    cases.append(
        (
            "invalid_outbound_fingerprint",
            invalid_outbound_fingerprint,
            "outbounds[0].settings.fingerprint invalid",
        )
    )

    invalid_inbound_private_key = copy.deepcopy(base_cfg)
    invalid_inbound_private_key["inbounds"] = [
        {
            "type": "reality",
            "tag": "reality-in",
            "settings": {
                "host": "127.0.0.1",
                "port": allocate_tcp_port(),
                "sni": "localhost",
                "site_port": 443,
                "private_key": "xyz",
                "short_id": "0102030405060708",
                "replay_cache_max_entries": 1000,
            },
        }
    ]
    invalid_inbound_private_key["outbounds"] = [{"type": "direct", "tag": "direct"}]
    invalid_inbound_private_key["routing"] = [{"type": "inbound", "values": ["reality-in"], "out": "direct"}]
    cases.append(
        (
            "invalid_inbound_private_key",
            invalid_inbound_private_key,
            "inbounds[0].settings.private_key hex length invalid",
        )
    )

    invalid_inbound_short_id = copy.deepcopy(base_cfg)
    invalid_inbound_short_id["inbounds"] = [
        {
            "type": "reality",
            "tag": "reality-in",
            "settings": {
                "host": "127.0.0.1",
                "port": allocate_tcp_port(),
                "sni": "localhost",
                "site_port": 443,
                "private_key": private_key,
                "short_id": "xyz",
                "replay_cache_max_entries": 1000,
            },
        }
    ]
    invalid_inbound_short_id["outbounds"] = [{"type": "direct", "tag": "direct"}]
    invalid_inbound_short_id["routing"] = [{"type": "inbound", "values": ["reality-in"], "out": "direct"}]
    cases.append(
        (
            "invalid_inbound_short_id",
            invalid_inbound_short_id,
            "inbounds[0].settings.short_id hex length invalid",
        )
    )

    for case_name, config_value, expected_error in cases:
        run_invalid_reality_config_case(binary, runtime_env, temp_root, case_name, config_value, expected_error)
        print(f"{case_name} ok")


def run_invalid_route_config_case(binary, runtime_env, temp_root):
    cfg = dump_default_config(binary, runtime_env)
    cfg["routing"][0]["out"] = "missing-outbound"

    config_path = temp_root / "invalid_route.json"
    save_json(config_path, cfg)

    result = subprocess.run([str(binary), "-c", str(config_path)], env=runtime_env, text=True, capture_output=True, check=False)
    if result.returncode == 0:
        raise RuntimeError("invalid_route unexpectedly succeeded")

    combined = (result.stdout or "") + (result.stderr or "")
    if "routing[0] outbound_not_found" not in combined:
        raise RuntimeError(f"invalid_route missing outbound_not_found output={combined!r}")
    assert_no_usage("invalid_route", combined)


def run_invalid_general_config_cases(binary, runtime_env, temp_root):
    base_cfg = dump_default_config(binary, runtime_env)

    invalid_port = copy.deepcopy(base_cfg)
    invalid_port["inbounds"][0]["settings"]["port"] = 70000
    run_invalid_config_value_case(
        binary,
        runtime_env,
        temp_root,
        "invalid_socks_port_overflow",
        invalid_port,
        "inbounds[0].settings.port out_of_range",
    )

    invalid_auth_username = copy.deepcopy(base_cfg)
    invalid_auth_username["inbounds"][0]["settings"]["auth"] = True
    run_invalid_config_value_case(
        binary,
        runtime_env,
        temp_root,
        "invalid_socks_auth_missing_username",
        invalid_auth_username,
        "inbounds[0].settings.username required_when_auth_enabled",
    )

    invalid_auth_password = copy.deepcopy(base_cfg)
    invalid_auth_password["inbounds"][0]["settings"]["auth"] = True
    invalid_auth_password["inbounds"][0]["settings"]["username"] = "user"
    run_invalid_config_value_case(
        binary,
        runtime_env,
        temp_root,
        "invalid_socks_auth_missing_password",
        invalid_auth_password,
        "inbounds[0].settings.password required_when_auth_enabled",
    )

    invalid_tun_prefix = copy.deepcopy(base_cfg)
    invalid_tun_prefix["inbounds"] = [
        {
            "type": "tun",
            "tag": "tun-in",
            "settings": {
                "name": "socks-test",
                "mtu": 1500,
                "ipv4": "198.18.0.1",
                "ipv4_prefix": 33,
                "ipv6": "fd00::1",
                "ipv6_prefix": 128,
            },
        }
    ]
    invalid_tun_prefix["routing"] = [{"type": "inbound", "values": ["tun-in"], "out": "direct"}]
    run_invalid_config_value_case(
        binary,
        runtime_env,
        temp_root,
        "invalid_tun_ipv4_prefix",
        invalid_tun_prefix,
        "inbounds[0].settings.ipv4_prefix out_of_range",
    )


def main():
    parser = argparse.ArgumentParser(description="Config dump/parse smoke test")
    parser.add_argument("--binary", default=str(pathlib.Path("build") / "socks"), help="path to the socks binary")
    parser.add_argument("--keep-artifacts", action="store_true")
    args = parser.parse_args()

    repo_root = pathlib.Path(__file__).resolve().parents[1]
    binary = pathlib.Path(args.binary)
    if not binary.is_absolute():
        binary = (repo_root / binary).resolve()
    if not binary.is_file() or not binary.exists():
        raise RuntimeError(f"binary not found: {binary}")
    temp_root = pathlib.Path(tempfile.mkdtemp(prefix=".tmp-config-roundtrip.", dir=repo_root))
    try:
        runtime_env = build_runtime_env(binary)
        run_default_roundtrip(binary, runtime_env, temp_root)
        print("default_roundtrip ok")
        run_marked_roundtrip(binary, runtime_env, temp_root)
        print("marked_roundtrip ok")
        run_socks_outbound_auth_guard_case(binary, runtime_env, temp_root)
        print("socks_outbound_auth_guard ok")
        run_socks_udp_outbound_reply_guard_case(binary, runtime_env, temp_root)
        print("socks_udp_outbound_reply_guard ok")
        run_invalid_config_case(binary, runtime_env, temp_root)
        print("invalid_config ok")
        run_invalid_reality_config_cases(binary, runtime_env, temp_root)
        run_invalid_general_config_cases(binary, runtime_env, temp_root)
        print("invalid_general_config ok")
        run_invalid_route_config_case(binary, runtime_env, temp_root)
        print("invalid_route ok")
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
