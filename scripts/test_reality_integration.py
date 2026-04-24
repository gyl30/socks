#!/usr/bin/env python3

import argparse
import json
import os
import pathlib
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from testlib import (
    allocate_tcp_port,
    allocate_udp_port,
    build_cert,
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
            raise RuntimeError("unexpected eof")
        data.extend(chunk)
    return bytes(data)


class FakeSocksUdpEchoServer:
    def __init__(self, expected_sessions=1):
        self.expected_sessions = expected_sessions
        self.error = None
        self.tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp_server.bind(("127.0.0.1", 0))
        self.tcp_server.listen(expected_sessions)
        self.udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_server.bind(("127.0.0.1", 0))
        self.tcp_port = self.tcp_server.getsockname()[1]
        self.udp_host, self.udp_port = self.udp_server.getsockname()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def close(self):
        for sock in (self.tcp_server, self.udp_server):
            try:
                sock.close()
            except OSError:
                pass

    def join(self):
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise RuntimeError("fake socks udp echo server did not exit")
        if self.error is not None:
            raise self.error

    def _serve(self):
        tcp_sockets = []
        try:
            self.tcp_server.settimeout(10)
            self.udp_server.settimeout(10)
            for _ in range(self.expected_sessions):
                conn, _peer = self.tcp_server.accept()
                tcp_sockets.append(conn)
                recv_exact(conn, 3)
                conn.sendall(b"\x05\x00")
                recv_exact(conn, 10)
                reply = bytearray(b"\x05\x00\x00\x01")
                reply.extend(socket.inet_aton(self.udp_host))
                reply.extend(struct.pack("!H", self.udp_port))
                conn.sendall(reply)

                packet, sender = self.udp_server.recvfrom(65535)
                self.udp_server.sendto(packet, sender)
        except Exception as exc:
            self.error = exc
        finally:
            for conn in tcp_sockets:
                try:
                    conn.close()
                except OSError:
                    pass
            self.close()


def fetch_json(url):
    with urllib.request.urlopen(url, timeout=2) as response:
        return json.load(response)


def wait_for_https_proxy_ready(proxy_url, cert_path, https_url, deadline_seconds, processes):
    deadline = time.time() + deadline_seconds
    last_error = ""
    args = [
        "curl",
        "--silent",
        "--show-error",
        "--fail",
        "--connect-timeout",
        "5",
        "--max-time",
        "20",
        "--proxy",
        proxy_url,
        "--cacert",
        str(cert_path),
        https_url,
    ]

    while time.time() < deadline:
        for process in processes:
            if process.process.poll() is not None:
                raise RuntimeError("proxy owner process exited early")

        result = subprocess.run(args, text=True, capture_output=True)
        if result.returncode == 0 and result.stdout == "ok-https\n":
            return result.stdout

        last_error = (result.stderr or result.stdout or f"rc={result.returncode}").strip()
        time.sleep(0.2)

    raise RuntimeError(f"timeout waiting for https proxy ready last_error={last_error}")


def wait_for_reality_multi_outbound_trace(web_port):
    deadline = time.time() + 5.0
    last_payload = None
    while time.time() < deadline:
        payload = fetch_json(f"http://127.0.0.1:{web_port}/api/traces/events?stage=route_decide_done&limit=100")
        last_payload = payload
        events = payload.get("items") or payload.get("events") or []
        reality_events = [
            event
            for event in events
            if event.get("inbound_tag") == "reality-in" and event.get("target_host") in {"127.0.0.2", "127.0.0.3"}
        ]
        tags_by_target = {event.get("target_host"): event.get("outbound_tag") for event in reality_events}
        if tags_by_target.get("127.0.0.2") == "socks-out-a" and tags_by_target.get("127.0.0.3") == "socks-out-b":
            return
        time.sleep(0.1)
    raise RuntimeError(f"missing reality udp multi outbound trace events: {last_payload}")


def main():
    parser = argparse.ArgumentParser(description="Local-stack end-to-end reality integration test")
    parser.add_argument("--binary", default=str(pathlib.Path("build") / "socks"), help="path to the socks binary")
    parser.add_argument("--real-url", default=os.environ.get("REAL_HTTPS_URL", ""), help="optional public HTTPS URL to test through SOCKS")
    parser.add_argument("--keep-artifacts", action="store_true")
    args = parser.parse_args()

    repo_root = pathlib.Path(__file__).resolve().parents[1]
    binary = pathlib.Path(args.binary)
    if not binary.is_absolute():
        binary = (repo_root / binary).resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError(f"binary not found: {binary}")

    for command_name in ("python3", "curl", "openssl"):
        if shutil.which(command_name) is None:
            raise RuntimeError(f"missing dependency: {command_name}")

    temp_root = pathlib.Path(tempfile.mkdtemp(prefix=".tmp-reality-integration.", dir=repo_root))
    helper_processes = []
    fake_socks_server = None
    try:
        runtime_env = build_runtime_env(binary)
        server_port = allocate_tcp_port()
        socks_port = allocate_tcp_port()
        https_port = allocate_tcp_port()
        web_port = allocate_tcp_port()
        udp_port = allocate_udp_port()

        origin_host = "localhost"
        socks_host = "127.0.0.1"
        reality_sni = "www.example.com"

        key_output = run_checked([str(binary), "x25519"], env=runtime_env, capture_output=True)
        private_key, public_key = parse_key_output(key_output.stdout)

        key_path, cert_path = build_cert(temp_root, origin_host)
        server_log = temp_root / "server.log"
        client_log = temp_root / "client.log"
        https_log = temp_root / "https.log"
        udp_log = temp_root / "udp.log"
        fake_socks_server = FakeSocksUdpEchoServer(expected_sessions=2)

        https_process = start_process(
            [
                sys.executable,
                str(repo_root / "scripts/https_static_server.py"),
                "--host",
                "127.0.0.1",
                "--port",
                str(https_port),
                "--certfile",
                str(cert_path),
                "--keyfile",
                str(key_path),
                "--response-text",
                "ok-https",
            ],
            str(https_log),
        )
        helper_processes.append(https_process)

        udp_process = start_process(
            [
                sys.executable,
                str(repo_root / "scripts/socks5_udp_echo_server.py"),
                "--host",
                "127.0.0.1",
                "--port",
                str(udp_port),
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
            "inbounds": [
                {
                    "type": "reality",
                    "tag": "reality-in",
                    "settings": {
                        "host": "127.0.0.1",
                        "port": server_port,
                        "sni": reality_sni,
                        "private_key": private_key,
                        "public_key": public_key,
                        "short_id": "0102030405060708",
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
                    "type": "socks",
                    "tag": "socks-out-a",
                    "settings": {
                        "host": "127.0.0.1",
                        "port": fake_socks_server.tcp_port,
                        "auth": False,
                    },
                },
                {
                    "type": "socks",
                    "tag": "socks-out-b",
                    "settings": {
                        "host": "127.0.0.1",
                        "port": fake_socks_server.tcp_port,
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
                    "values": ["127.0.0.2/32"],
                    "out": "socks-out-a",
                },
                {
                    "type": "ip",
                    "values": ["127.0.0.3/32"],
                    "out": "socks-out-b",
                },
                {
                    "type": "inbound",
                    "values": ["reality-in"],
                    "out": "direct",
                }
            ],
            "timeout": {
                "read": 5,
                "write": 5,
                "connect": 5,
                "idle": 30,
            },
            "web": {
                "enabled": True,
                "host": "127.0.0.1",
                "port": web_port,
            },
        }

        client_cfg = {
            "workers": 1,
            "log": {
                "level": "debug",
                "file": str(client_log),
            },
            "inbounds": [
                {
                    "type": "socks",
                    "tag": "socks-in",
                    "settings": {
                        "host": socks_host,
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
                        "sni": reality_sni,
                        "fingerprint": "random",
                        "public_key": public_key,
                        "short_id": "0102030405060708",
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
            "timeout": {
                "read": 5,
                "write": 5,
                "connect": 5,
                "idle": 30,
            },
        }

        save_json(temp_root / "server.json", server_cfg)
        save_json(temp_root / "client.json", client_cfg)

        server_process = start_process(
            [str(binary), "-c", str(temp_root / "server.json")],
            str(server_log),
            extra_env=runtime_env,
        )
        helper_processes.append(server_process)

        client_process = start_process(
            [str(binary), "-c", str(temp_root / "client.json")],
            str(client_log),
            extra_env=runtime_env,
        )
        helper_processes.append(client_process)

        wait_for_log_text(server_log, f"listen 127.0.0.1:{server_port} reality inbound listening", 20, "server log")
        wait_for_log_text(client_log, f"listen {socks_host}:{socks_port} socks listening", 20, "client log")
        wait_for_port(socks_host, socks_port, 20, "socks5 proxy")
        wait_for_port("127.0.0.1", web_port, 20, "server trace web", [server_process, client_process])

        proxy_url = f"socks5://{socks_host}:{socks_port}"
        proxy_hostname_url = f"socks5h://{socks_host}:{socks_port}"
        https_url = f"https://{origin_host}:{https_port}/healthz.txt"

        first_body = wait_for_https_proxy_ready(
            proxy_url,
            cert_path,
            https_url,
            20,
            [server_process, client_process, https_process],
        )
        if first_body != "ok-https\n":
            raise RuntimeError(f"unexpected https response {first_body!r}")

        parallel_dir = temp_root / "parallel"
        parallel_dir.mkdir(parents=True, exist_ok=True)
        curl_jobs = []
        for index in range(4):
            out_path = parallel_dir / f"{index + 1}.out"
            out_handle = open(out_path, "w", encoding="utf-8")
            process = subprocess.Popen(
                [
                    "curl",
                    "--silent",
                    "--show-error",
                    "--fail",
                    "--connect-timeout",
                    "5",
                    "--max-time",
                    "20",
                    "--proxy",
                    proxy_url,
                    "--cacert",
                    str(cert_path),
                    https_url,
                ],
                stdout=out_handle,
                stderr=subprocess.STDOUT,
                text=True,
            )
            curl_jobs.append((process, out_handle, out_path))

        for process, out_handle, out_path in curl_jobs:
            rc = process.wait(timeout=30)
            out_handle.close()
            if rc != 0:
                raise RuntimeError(f"parallel https request failed rc={rc} output={tail_file(out_path, 20)}")
            if out_path.read_text(encoding="utf-8").strip() != "ok-https":
                raise RuntimeError(f"unexpected parallel https response {out_path.read_text(encoding='utf-8')!r}")

        server_text = tail_file(server_log, 120)
        if f"authorized sni {reality_sni}" not in server_text:
            raise RuntimeError(f"missing reality sni log for {reality_sni}")

        https_text = tail_file(https_log, 120)
        if "sni=localhost" not in https_text:
            raise RuntimeError("missing upstream https sni log for localhost")

        udp_result = run_checked(
            [
                sys.executable,
                str(repo_root / "scripts/socks5_udp_client.py"),
                "--socks-host",
                socks_host,
                "--socks-port",
                str(socks_port),
                "--target-host",
                "127.0.0.1",
                "--target-port",
                str(udp_port),
                "--payload",
                "udp-smoke",
            ],
            capture_output=True,
        )
        if udp_result.stdout.strip() != "udp-smoke":
            raise RuntimeError(f"unexpected udp response {udp_result.stdout!r}")

        multi_udp_result = run_checked(
            [
                sys.executable,
                str(repo_root / "scripts/socks5_udp_multi_target.py"),
                "--socks-host",
                socks_host,
                "--socks-port",
                str(socks_port),
                "--target-a-host",
                "127.0.0.2",
                "--target-a-port",
                "53101",
                "--target-b-host",
                "127.0.0.3",
                "--target-b-port",
                "53102",
            ],
            capture_output=True,
        )
        if multi_udp_result.stdout.strip() != "socks5 udp multi target ok":
            raise RuntimeError(f"unexpected multi udp response {multi_udp_result.stdout!r}")
        fake_socks_server.join()
        wait_for_reality_multi_outbound_trace(web_port)

        if args.real_url:
            real_result = run_checked(
                [
                    "curl",
                    "--silent",
                    "--show-error",
                    "--fail",
                    "--connect-timeout",
                    "8",
                    "--max-time",
                    "30",
                    "--proxy",
                    proxy_hostname_url,
                    args.real_url,
                ],
                capture_output=True,
            )
            sys.stdout.write(real_result.stdout)

        print("reality_https_proxy ok")
        print("reality_sni_hijack ok")
        print("parallel_proxy ok")
        print("udp_associate ok")
        print("reality_udp_multi_outbound ok")
        if args.real_url:
            print("real_https_url ok")
        return 0
    except Exception as exc:
        print(f"test failed {exc}", file=sys.stderr)
        print("===== server.log =====", file=sys.stderr)
        print(tail_file(temp_root / "server.log"), file=sys.stderr)
        print("===== client.log =====", file=sys.stderr)
        print(tail_file(temp_root / "client.log"), file=sys.stderr)
        print("===== https.log =====", file=sys.stderr)
        print(tail_file(temp_root / "https.log"), file=sys.stderr)
        print("===== udp.log =====", file=sys.stderr)
        print(tail_file(temp_root / "udp.log"), file=sys.stderr)
        raise
    finally:
        if fake_socks_server is not None:
            fake_socks_server.close()
        for process in reversed(helper_processes):
            try:
                process.terminate()
            except Exception:
                pass
        if args.keep_artifacts:
            print(f"artifacts kept at {temp_root}", file=sys.stderr)
        else:
            subprocess.run(["rm", "-rf", str(temp_root)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    raise SystemExit(main())
