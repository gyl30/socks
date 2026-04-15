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


def allocate_tcp_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def save_json(path, value):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2)
        handle.write("\n")


def build_runtime_env(binary):
    runtime_dirs = []

    def append_runtime_dir(path):
        if not path or not os.path.isdir(path) or path in runtime_dirs:
            return
        runtime_dirs.append(path)

    def append_runtime_dirs(raw):
        if not raw:
            return
        for path in raw.split(":"):
            append_runtime_dir(path)

    def append_root_runtime_dirs(root):
        if not root:
            return
        append_runtime_dir(os.path.join(root, "lib64"))
        append_runtime_dir(os.path.join(root, "lib"))

    def read_binary_runpath(path):
        try:
            result = subprocess.run(["readelf", "-d", str(path)], text=True, capture_output=True, check=False)
        except FileNotFoundError:
            return ""
        if result.returncode != 0:
            return ""
        match = re.search(r"\((?:RUNPATH|RPATH)\).*?\[(.*?)\]", result.stdout)
        if match is None:
            return ""
        return match.group(1)

    append_runtime_dirs(os.environ.get("SOCKS_RUNTIME_LIB_DIRS", ""))
    append_root_runtime_dirs(os.environ.get("OPENSSL_ROOT_DIR", ""))
    append_root_runtime_dirs(os.environ.get("BROTLI_ROOT_DIR", ""))
    append_runtime_dirs(read_binary_runpath(binary))
    append_runtime_dirs(os.environ.get("LD_LIBRARY_PATH", ""))
    if not runtime_dirs:
        return {}
    return {"LD_LIBRARY_PATH": ":".join(runtime_dirs)}


def parse_key_output(output):
    private_match = re.search(r"private key:\s+(\S+)", output)
    public_match = re.search(r"public key:\s+(\S+)", output)
    if private_match is None or public_match is None:
        raise RuntimeError("failed to parse x25519 key output")
    return private_match.group(1), public_match.group(1)


def wait_for_port(host, port, deadline_seconds, label, processes=None):
    deadline = time.time() + deadline_seconds
    last_error = None
    while time.time() < deadline:
        if processes is not None:
            for process in processes:
                if process.process.poll() is not None:
                    raise RuntimeError(f"process exited early while waiting for {label}")
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


def tail_file(path, lines=120):
    if not path.exists():
        return ""
    data = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(data[-lines:])


def wait_for_log_text(path, needle, deadline_seconds, label, processes=None):
    deadline = time.time() + deadline_seconds
    while time.time() < deadline:
        if processes is not None:
            for process in processes:
                if process.process.poll() is not None:
                    raise RuntimeError(f"process exited early while waiting for {label}")
        if path.exists():
            text = path.read_text(encoding="utf-8", errors="replace")
            if needle in text:
                return text
        time.sleep(0.2)
    raise RuntimeError(f"timeout waiting for {label} log text {needle!r}")


def fetch_json(url, proxy_url=None):
    args = [
        "curl",
        "--silent",
        "--show-error",
        "--fail",
        "--max-time",
        "20",
    ]
    if proxy_url is not None:
        args.extend(["--socks5-hostname", proxy_url])
    args.append(url)
    result = run_checked(args, capture_output=True)
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser(description="trace web integration test")
    parser.add_argument("--binary", default=str(pathlib.Path("build") / "socks"), help="path to the socks binary")
    parser.add_argument("--keep-artifacts", action="store_true")
    args = parser.parse_args()

    repo_root = pathlib.Path(__file__).resolve().parents[1]
    binary = pathlib.Path(args.binary)
    if not binary.is_absolute():
        binary = (repo_root / binary).resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError(f"binary not found: {binary}")

    for command_name in ("python3", "curl"):
        if shutil.which(command_name) is None:
            raise RuntimeError(f"missing dependency: {command_name}")

    temp_root = pathlib.Path(tempfile.mkdtemp(prefix=".tmp-trace-web.", dir=repo_root))
    helper_processes = []
    try:
        runtime_env = build_runtime_env(binary)
        web_port = allocate_tcp_port()
        socks_port = allocate_tcp_port()
        http_port = allocate_tcp_port()
        reality_port = allocate_tcp_port()
        server_socks_port = allocate_tcp_port()

        key_output = run_checked([str(binary), "x25519"], env=runtime_env, capture_output=True)
        private_key, public_key = parse_key_output(key_output.stdout)
        short_id = "0102030405060708"
        sni = "www.example.com"

        http_root = temp_root / "http"
        http_root.mkdir(parents=True, exist_ok=True)
        (http_root / "healthz.txt").write_text("ok-trace-web\n", encoding="utf-8")

        server_log = temp_root / "server.log"
        client_log = temp_root / "client.log"
        http_log = temp_root / "http.log"

        server_cfg = {
            "workers": 1,
            "log": {
                "level": "debug",
                "file": str(server_log),
            },
            "timeout": {
                "read": 10,
                "write": 10,
                "connect": 10,
                "idle": 60,
            },
            "inbounds": [
                {
                    "type": "reality",
                    "tag": "reality-in",
                    "settings": {
                        "host": "127.0.0.1",
                        "port": reality_port,
                        "sni": sni,
                        "private_key": private_key,
                        "public_key": public_key,
                        "short_id": short_id,
                        "replay_cache_max_entries": 100000,
                    },
                },
                {
                    "type": "socks",
                    "tag": "socks-in-server",
                    "settings": {
                        "host": "127.0.0.1",
                        "port": server_socks_port,
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
                    "type": "block",
                    "tag": "block",
                },
                {
                    "type": "socks",
                    "tag": "socks-out",
                    "settings": {
                        "host": "127.0.0.1",
                        "port": server_socks_port,
                        "auth": False,
                    },
                },
            ],
            "routing": [
                {
                    "type": "inbound",
                    "values": ["reality-in", "socks-in-server"],
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
                "read": 10,
                "write": 10,
                "connect": 10,
                "idle": 60,
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
                        "port": reality_port,
                        "sni": sni,
                        "fingerprint": "random",
                        "public_key": public_key,
                        "short_id": short_id,
                        "max_handshake_records": 256,
                    },
                },
                {
                    "type": "socks",
                    "tag": "socks-out",
                    "settings": {
                        "host": "127.0.0.1",
                        "port": server_socks_port,
                        "auth": False,
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
                    "out": "direct",
                }
            ],
        }

        save_json(temp_root / "server.json", server_cfg)
        save_json(temp_root / "client.json", client_cfg)

        http_process = ManagedProcess(
            [
                sys.executable,
                "-m",
                "http.server",
                str(http_port),
                "--bind",
                "127.0.0.1",
                "--directory",
                str(http_root),
            ],
            str(http_log),
        )
        helper_processes.append(http_process)

        server_process = ManagedProcess([str(binary), "-c", str(temp_root / "server.json")], str(temp_root / "server.stdout.log"), extra_env=runtime_env)
        helper_processes.append(server_process)
        wait_for_log_text(server_log, "reality inbound listening", 20, "reality_inbound", helper_processes)
        wait_for_log_text(server_log, "socks listening", 20, "server_socks_inbound", helper_processes)

        client_process = ManagedProcess([str(binary), "-c", str(temp_root / "client.json")], str(temp_root / "client.stdout.log"), extra_env=runtime_env)
        helper_processes.append(client_process)
        wait_for_log_text(client_log, "socks listening", 20, "client_socks_inbound", helper_processes)
        wait_for_port("127.0.0.1", web_port, 20, "trace_web", helper_processes)

        fetch_json(f"http://127.0.0.1:{web_port}/", proxy_url=None)
        run_checked(
            [
                "curl",
                "--silent",
                "--show-error",
                "--fail",
                "--max-time",
                "20",
                "--socks5-hostname",
                f"127.0.0.1:{socks_port}",
                f"http://127.0.0.1:{http_port}/healthz.txt",
            ],
            capture_output=True,
        )

        stats = fetch_json(f"http://127.0.0.1:{web_port}/api/traces/stats")
        if stats.get("total_sessions") != 1:
            raise RuntimeError(f"unexpected total_sessions: {stats}")
        if stats.get("success_sessions") != 1:
            raise RuntimeError(f"unexpected success_sessions: {stats}")
        if stats.get("failed_sessions") != 0:
            raise RuntimeError(f"unexpected failed_sessions: {stats}")
        if stats.get("total_events") != 9:
            raise RuntimeError(f"unexpected total_events: {stats}")

        trace_list = fetch_json(f"http://127.0.0.1:{web_port}/api/traces")
        if trace_list.get("count") != 1:
            raise RuntimeError(f"unexpected trace list count: {trace_list}")
        items = trace_list.get("items", [])
        if len(items) != 1:
            raise RuntimeError(f"unexpected trace list items: {trace_list}")

        trace_id = items[0].get("trace_id")
        if not isinstance(trace_id, str) or len(trace_id) != 16:
            raise RuntimeError(f"unexpected trace_id: {trace_id}")

        filtered_list = fetch_json(f"http://127.0.0.1:{web_port}/api/traces?status=success&inbound_tag=socks-in")
        if filtered_list.get("count") != 1:
            raise RuntimeError(f"unexpected filtered list: {filtered_list}")

        detail = fetch_json(f"http://127.0.0.1:{web_port}/api/traces/{trace_id}")
        summary = detail.get("summary", {})
        events = detail.get("events", [])
        if summary.get("trace_id") != trace_id:
            raise RuntimeError(f"unexpected detail summary: {detail}")
        if summary.get("status") != "success":
            raise RuntimeError(f"unexpected detail status: {detail}")
        if summary.get("outbound_type") != "direct":
            raise RuntimeError(f"unexpected detail outbound_type: {detail}")
        if summary.get("events_count") != 9:
            raise RuntimeError(f"unexpected summary events_count: {detail}")
        if len(events) != 9:
            raise RuntimeError(f"unexpected detail events: {detail}")

        events_only = fetch_json(f"http://127.0.0.1:{web_port}/api/traces/{trace_id}/events")
        if events_only.get("trace_id") != trace_id:
            raise RuntimeError(f"unexpected events trace_id: {events_only}")
        if events_only.get("count") != 9:
            raise RuntimeError(f"unexpected events count: {events_only}")
        event_items = events_only.get("events", [])
        if len(event_items) != 9:
            raise RuntimeError(f"unexpected events payload: {events_only}")
        connect_events = [item for item in event_items if item.get("stage") == "outbound_connect_start"]
        if len(connect_events) != 1:
            raise RuntimeError(f"unexpected connect events: {events_only}")
        if connect_events[0].get("outbound_type") != "direct":
            raise RuntimeError(f"unexpected outbound_type in event: {events_only}")

        print("trace web integration ok")
    except Exception:
        if temp_root.exists():
            for log_name in ("server.stdout.log", "client.stdout.log", "server.log", "client.log", "http.log"):
                log_path = temp_root / log_name
                if log_path.exists():
                    print(f"===== {log_name} =====", file=sys.stderr)
                    print(tail_file(log_path), file=sys.stderr)
        raise
    finally:
        for process in reversed(helper_processes):
            try:
                process.terminate()
            except Exception:
                pass
        if args.keep_artifacts:
            print(f"test artifacts kept at {temp_root}")
        else:
            shutil.rmtree(temp_root, ignore_errors=True)


if __name__ == "__main__":
    main()
