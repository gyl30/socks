#!/usr/bin/env python3

import argparse
import json
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time


class ManagedProcess:
    def __init__(self, args, stdout_path, extra_env=None):
        self.stdout_path = stdout_path
        self.stdout_handle = open(stdout_path, "w", encoding="utf-8")
        env = os.environ.copy()
        if extra_env is not None:
            env.update(extra_env)
        self.process = subprocess.Popen(args, stdout=self.stdout_handle, stderr=subprocess.STDOUT, text=True, env=env)

    def terminate(self):
        if self.process.poll() is None:
            self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        self.stdout_handle.close()


def run_checked(args, cwd=None, env=None, capture_output=False):
    result = subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=capture_output)
    if result.returncode != 0:
        stdout = result.stdout if result.stdout is not None else ""
        stderr = result.stderr if result.stderr is not None else ""
        raise RuntimeError(f"command failed: {' '.join(args)}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    return result


def wait_for_port(host, port, deadline_seconds, label):
    deadline = time.time() + deadline_seconds
    last_error = None
    while time.time() < deadline:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.2)
        try:
            sock.connect((host, port))
            return
        except OSError as exc:
            last_error = exc
            time.sleep(0.2)
        finally:
            sock.close()
    raise RuntimeError(f"timeout waiting for {label} {host}:{port} last_error={last_error}")


def wait_for_log_text(path, needle, deadline_seconds, label):
    deadline = time.time() + deadline_seconds
    while time.time() < deadline:
        if path.exists():
            text = path.read_text(encoding="utf-8", errors="replace")
            if needle in text:
                return text
        time.sleep(0.2)
    raise RuntimeError(f"timeout waiting for log text {needle!r} in {label}")


def tail_file(path, lines=80):
    if not path.exists():
        return ""
    data = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(data[-lines:])


def allocate_tcp_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def allocate_udp_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def save_json(path, value):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2)
        handle.write("\n")


def parse_key_output(output):
    private_match = re.search(r"private key:\s+(\S+)", output)
    public_match = re.search(r"public key:\s+(\S+)", output)
    if private_match is None or public_match is None:
        raise RuntimeError("failed to parse x25519 key output")
    return private_match.group(1), public_match.group(1)


def build_cert(tmp_dir, hostname):
    key_path = tmp_dir / "origin.key"
    cert_path = tmp_dir / "origin.crt"
    openssl_conf = tmp_dir / "openssl.cnf"
    openssl_conf.write_text(
        "\n".join(
            [
                "[req]",
                "distinguished_name = req_distinguished_name",
                "x509_extensions = v3_req",
                "prompt = no",
                "",
                "[req_distinguished_name]",
                f"CN = {hostname}",
                "",
                "[v3_req]",
                "subjectAltName = @alt_names",
                "",
                "[alt_names]",
                f"DNS.1 = {hostname}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    run_checked(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
            "-config",
            str(openssl_conf),
            "-extensions",
            "v3_req",
        ]
    )
    return key_path, cert_path


def start_process(args, stdout_path, extra_env=None):
    return ManagedProcess(args, stdout_path, extra_env=extra_env)


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
    try:
        server_port = allocate_tcp_port()
        socks_port = allocate_tcp_port()
        https_port = allocate_tcp_port()
        udp_port = allocate_udp_port()

        origin_host = "localhost"
        socks_host = "127.0.0.1"
        reality_sni = "www.example.com"

        key_output = run_checked([str(binary), "x25519"], capture_output=True)
        private_key, public_key = parse_key_output(key_output.stdout)

        key_path, cert_path = build_cert(temp_root, origin_host)
        server_log = temp_root / "server.log"
        client_log = temp_root / "client.log"
        https_log = temp_root / "https.log"
        udp_log = temp_root / "udp.log"

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
            "mode": "server",
            "workers": 1,
            "log": {
                "level": "debug",
                "file": str(server_log),
            },
            "inbound": {
                "host": "127.0.0.1",
                "port": server_port,
            },
            "socks": {
                "enabled": False,
            },
            "reality": {
                "sni": reality_sni,
                "private_key": private_key,
                "public_key": public_key,
                "short_id": "0102030405060708",
            },
            "timeout": {
                "read": 5,
                "write": 5,
                "connect": 5,
                "idle": 30,
            },
            "limits": {
                "max_connections": 64,
                "max_buffer": 10485760,
                "max_streams": 256,
                "max_handshake_records": 256,
            },
            "monitor": {
                "enabled": False,
                "port": 0,
            },
        }

        client_cfg = {
            "mode": "client",
            "workers": 1,
            "log": {
                "level": "debug",
                "file": str(client_log),
            },
            "socks": {
                "enabled": True,
                "host": socks_host,
                "port": socks_port,
                "auth": False,
            },
            "tproxy": {
                "enabled": False,
                "listen_host": "::",
                "tcp_port": 0,
                "udp_port": 0,
                "mark": 17,
            },
            "outbound": {
                "host": "127.0.0.1",
                "port": server_port,
            },
            "reality": {
                "sni": reality_sni,
                "fingerprint": "random",
                "public_key": public_key,
                "short_id": "0102030405060708",
            },
            "timeout": {
                "read": 5,
                "write": 5,
                "connect": 5,
                "idle": 30,
            },
            "limits": {
                "max_connections": 4,
                "max_buffer": 10485760,
                "max_streams": 256,
                "max_handshake_records": 256,
            },
            "heartbeat": {
                "enabled": True,
                "idle_timeout": 10,
                "min_interval": 15,
                "max_interval": 45,
                "min_padding": 32,
                "max_padding": 128,
            },
            "monitor": {
                "enabled": False,
                "port": 0,
            },
        }

        save_json(temp_root / "server.json", server_cfg)
        save_json(temp_root / "client.json", client_cfg)

        server_process = start_process([str(binary), "-c", str(temp_root / "server.json")], str(server_log))
        helper_processes.append(server_process)

        client_process = start_process([str(binary), "-c", str(temp_root / "client.json")], str(client_log))
        helper_processes.append(client_process)

        wait_for_log_text(server_log, f"remote server listening on 127.0.0.1:{server_port}", 20, "server log")
        wait_for_log_text(client_log, f"local socks5 listening on {socks_host}:{socks_port}", 20, "client log")
        wait_for_port(socks_host, socks_port, 20, "socks5 proxy")

        proxy_url = f"socks5h://{socks_host}:{socks_port}"
        https_url = f"https://{origin_host}:{https_port}/healthz.txt"

        first_result = run_checked(
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
            capture_output=True,
        )
        if first_result.stdout != "ok-https\n":
            raise RuntimeError(f"unexpected https response {first_result.stdout!r}")

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
                    proxy_url,
                    args.real_url,
                ],
                capture_output=True,
            )
            sys.stdout.write(real_result.stdout)

        print("reality_https_proxy ok")
        print("reality_sni_hijack ok")
        print("mux_parallel ok")
        print("udp_associate ok")
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
