#!/usr/bin/env python3

import argparse
import http.server
import json
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
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


class SlowHttpServer:
    def __init__(self, host, port, pause_seconds=2.5):
        self._server = http.server.ThreadingHTTPServer((host, port), self._build_handler())
        self._server.pause_seconds = pause_seconds
        self._server.first_chunk_sent = threading.Event()
        self._server.first_chunk = b"a" * 65536
        self._server.second_chunk = b"b" * 131072
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @staticmethod
    def _build_handler():
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path != "/stream":
                    self.send_error(404)
                    return

                first_chunk = self.server.first_chunk
                second_chunk = self.server.second_chunk
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(first_chunk) + len(second_chunk)))
                self.end_headers()
                self.wfile.write(first_chunk)
                self.wfile.flush()
                self.server.first_chunk_sent.set()
                time.sleep(self.server.pause_seconds)
                self.wfile.write(second_chunk)
                self.wfile.flush()

            def log_message(self, fmt, *args):
                return

        return Handler

    def start(self):
        self._thread.start()

    def wait_for_first_chunk(self, timeout_seconds):
        if not self._server.first_chunk_sent.wait(timeout_seconds):
            raise RuntimeError("timeout waiting for slow http first chunk")

    def terminate(self):
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


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


def fetch_text(url, proxy_url=None):
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
    return result.stdout


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
    slow_http_server = None
    try:
        runtime_env = build_runtime_env(binary)
        web_port = allocate_tcp_port()
        socks_port = allocate_tcp_port()
        http_port = allocate_tcp_port()
        slow_http_port = allocate_tcp_port()
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
        dashboard_html = fetch_text(f"http://127.0.0.1:{web_port}/dashboard")
        if "Trace Dashboard" not in dashboard_html or "trace-dashboard" not in dashboard_html:
            raise RuntimeError("unexpected dashboard html payload")
        for needle in (
            'id="traffic-chart"',
            'id="trace-query-form"',
            'id="trace-table"',
            'id="trace-modal"',
            'id="trace-summary"',
            'id="trace-timeline"',
            'name="status"',
            'name="target_host"',
            'data-trace-toggle=',
            'data-modal-close="true"',
            'renderTrafficChart',
            'trafficWindowMinutes',
            'queryPath("/api/traces", state.tracesQuery)',
            'closeTraceModal',
            'fetchJson("/api/traces/" + traceId)',
            'fetchJson("/api/traces/" + traceId + "/events?sort_order=asc&limit=300")',
        ):
            if needle not in dashboard_html:
                raise RuntimeError(f"dashboard filter wiring missing: {needle}")
        if "请求生命周期总览" in dashboard_html:
            raise RuntimeError("stale lifecycle hero still present")
        if 'id="traffic-chart-meta"' in dashboard_html:
            raise RuntimeError("stale traffic chart hint still present")
        for needle in (
            'name="sort_field"',
            'name="sort_order"',
            'id="trace-query-meta"',
            "仅保留链路列表查询参数",
        ):
            if needle in dashboard_html:
                raise RuntimeError(f"dashboard stale filter hint still present: {needle}")
        if dashboard_html.find("运行状态") > dashboard_html.find('id="traffic-chart"'):
            raise RuntimeError("runtime stats should be rendered before traffic chart")
        for needle in (
            'id="events-query-form"',
            'id="events-stream"',
            'id="anomaly-list"',
            'id="anomaly-summary"',
            'trace-detail-row',
            'trace-inline-detail',
        ):
            if needle in dashboard_html:
                raise RuntimeError(f"dashboard stale section still present: {needle}")
        dashboard_initial = fetch_json(f"http://127.0.0.1:{web_port}/api/traces/dashboard")
        initial_history = dashboard_initial.get("traffic_history", [])
        if len(initial_history) < 1:
            raise RuntimeError(f"unexpected initial dashboard traffic_history: {dashboard_initial}")
        if initial_history[-1].get("total_tx_bytes") != 0:
            raise RuntimeError(f"unexpected initial dashboard total_tx_bytes: {dashboard_initial}")
        if initial_history[-1].get("total_rx_bytes") != 0:
            raise RuntimeError(f"unexpected initial dashboard total_rx_bytes: {dashboard_initial}")
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
                f"http://localhost:{http_port}/healthz.txt",
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

        dashboard = fetch_json(f"http://127.0.0.1:{web_port}/api/traces/dashboard")
        dashboard_stats = dashboard.get("stats", {})
        if dashboard_stats.get("total_sessions") != 1:
            raise RuntimeError(f"unexpected dashboard total_sessions: {dashboard}")
        if dashboard.get("status_counts", {}).get("success") != 1:
            raise RuntimeError(f"unexpected dashboard status_counts: {dashboard}")
        if dashboard.get("inbound_tag_counts", {}).get("socks-in") != 1:
            raise RuntimeError(f"unexpected dashboard inbound_tag_counts: {dashboard}")
        if dashboard.get("inbound_type_counts", {}).get("socks") != 1:
            raise RuntimeError(f"unexpected dashboard inbound_type_counts: {dashboard}")
        if dashboard.get("outbound_type_counts", {}).get("direct") != 1:
            raise RuntimeError(f"unexpected dashboard outbound_type_counts: {dashboard}")
        if dashboard.get("route_type_counts", {}).get("direct") != 1:
            raise RuntimeError(f"unexpected dashboard route_type_counts: {dashboard}")
        if dashboard.get("stage_event_counts", {}).get("route_decide_done") != 1:
            raise RuntimeError(f"unexpected dashboard stage_event_counts: {dashboard}")
        traffic_history = dashboard.get("traffic_history", [])
        if len(traffic_history) < 1:
            raise RuntimeError(f"unexpected dashboard traffic_history: {dashboard}")
        if traffic_history[-1].get("total_tx_bytes", 0) <= 0:
            raise RuntimeError(f"unexpected dashboard total_tx_bytes after request: {dashboard}")
        if traffic_history[-1].get("total_rx_bytes", 0) <= 0:
            raise RuntimeError(f"unexpected dashboard total_rx_bytes after request: {dashboard}")

        time.sleep(1.2)
        dashboard_after_sample = fetch_json(f"http://127.0.0.1:{web_port}/api/traces/dashboard")
        sampled_history = dashboard_after_sample.get("traffic_history", [])
        if len(sampled_history) < len(traffic_history):
            raise RuntimeError(f"unexpected sampled dashboard traffic_history: {dashboard_after_sample}")
        if sampled_history[-1].get("ts_unix_ms", 0) <= sampled_history[0].get("ts_unix_ms", 0):
            raise RuntimeError(f"unexpected sampled dashboard traffic ordering: {dashboard_after_sample}")
        if sampled_history[-1].get("total_tx_bytes", 0) != traffic_history[-1].get("total_tx_bytes", 0):
            raise RuntimeError(f"unexpected sampled dashboard total_tx_bytes persistence: {dashboard_after_sample}")
        if sampled_history[-1].get("total_rx_bytes", 0) != traffic_history[-1].get("total_rx_bytes", 0):
            raise RuntimeError(f"unexpected sampled dashboard total_rx_bytes persistence: {dashboard_after_sample}")

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
        if summary.get("target_host") != "localhost":
            raise RuntimeError(f"unexpected detail target_host: {detail}")
        if summary.get("resolved_target_host") != "127.0.0.1":
            raise RuntimeError(f"unexpected detail resolved_target_host: {detail}")
        if summary.get("resolved_target_port") != http_port:
            raise RuntimeError(f"unexpected detail resolved_target_port: {detail}")
        if summary.get("events_count") != 9:
            raise RuntimeError(f"unexpected summary events_count: {detail}")

        lifecycle = summary.get("lifecycle", {})
        if lifecycle.get("conn_accepted") is not True:
            raise RuntimeError(f"unexpected lifecycle conn_accepted: {detail}")
        if lifecycle.get("route_decide_done") is not True:
            raise RuntimeError(f"unexpected lifecycle route_decide_done: {detail}")
        if lifecycle.get("outbound_connect_done") is not True:
            raise RuntimeError(f"unexpected lifecycle outbound_connect_done: {detail}")
        if lifecycle.get("relay_start") is not True:
            raise RuntimeError(f"unexpected lifecycle relay_start: {detail}")
        if lifecycle.get("session_close") is not True:
            raise RuntimeError(f"unexpected lifecycle session_close: {detail}")
        stage_counts = summary.get("stage_counts", {})
        if stage_counts.get("conn_accepted") != 1:
            raise RuntimeError(f"unexpected stage_counts conn_accepted: {detail}")
        if stage_counts.get("route_decide_done") != 1:
            raise RuntimeError(f"unexpected stage_counts route_decide_done: {detail}")
        if len(events) != 9:
            raise RuntimeError(f"unexpected detail events: {detail}")

        global_events = fetch_json(f"http://127.0.0.1:{web_port}/api/traces/events")
        if global_events.get("total") != 9:
            raise RuntimeError(f"unexpected global events total: {global_events}")
        if global_events.get("count") != 9:
            raise RuntimeError(f"unexpected global events count: {global_events}")
        global_event_items = global_events.get("items", [])
        if len(global_event_items) != 9:
            raise RuntimeError(f"unexpected global event items: {global_events}")
        if global_event_items[0].get("stage") != "session_close":
            raise RuntimeError(f"unexpected global event order: {global_events}")

        filtered_events = fetch_json(
            f"http://127.0.0.1:{web_port}/api/traces/events?trace_id={trace_id}&stage=route_decide_done&result=ok&limit=1"
        )
        if filtered_events.get("total") != 1:
            raise RuntimeError(f"unexpected filtered events total: {filtered_events}")
        filtered_event_items = filtered_events.get("items", [])
        if len(filtered_event_items) != 1:
            raise RuntimeError(f"unexpected filtered events items: {filtered_events}")
        if filtered_event_items[0].get("trace_id") != trace_id:
            raise RuntimeError(f"unexpected filtered events trace_id: {filtered_events}")
        if filtered_event_items[0].get("stage") != "route_decide_done":
            raise RuntimeError(f"unexpected filtered events stage: {filtered_events}")

        events_only = fetch_json(f"http://127.0.0.1:{web_port}/api/traces/{trace_id}/events")
        if events_only.get("trace_id") != trace_id:
            raise RuntimeError(f"unexpected events trace_id: {events_only}")
        if events_only.get("total") != 9:
            raise RuntimeError(f"unexpected events total: {events_only}")
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
        connected_events = [item for item in event_items if item.get("stage") == "outbound_connect_done"]
        if len(connected_events) != 1:
            raise RuntimeError(f"unexpected connected events: {events_only}")
        if connected_events[0].get("resolved_target_host") != "127.0.0.1":
            raise RuntimeError(f"unexpected connected event resolved_target_host: {events_only}")
        if connected_events[0].get("resolved_target_port") != http_port:
            raise RuntimeError(f"unexpected connected event resolved_target_port: {events_only}")

        trace_filtered_events = fetch_json(
            f"http://127.0.0.1:{web_port}/api/traces/{trace_id}/events?stage=route_decide_done&sort_order=asc&limit=1"
        )
        if trace_filtered_events.get("trace_id") != trace_id:
            raise RuntimeError(f"unexpected trace filtered events trace_id: {trace_filtered_events}")
        if trace_filtered_events.get("total") != 1:
            raise RuntimeError(f"unexpected trace filtered events total: {trace_filtered_events}")
        if trace_filtered_events.get("count") != 1:
            raise RuntimeError(f"unexpected trace filtered events count: {trace_filtered_events}")
        trace_filtered_items = trace_filtered_events.get("events", [])
        if len(trace_filtered_items) != 1:
            raise RuntimeError(f"unexpected trace filtered events payload: {trace_filtered_events}")
        if trace_filtered_items[0].get("stage") != "route_decide_done":
            raise RuntimeError(f"unexpected trace filtered events stage: {trace_filtered_events}")

        slow_http_server = SlowHttpServer("127.0.0.1", slow_http_port)
        slow_http_server.start()
        wait_for_port("127.0.0.1", slow_http_port, 10, "slow_http", helper_processes)

        baseline_tx_bytes = int(dashboard_stats.get("total_tx_bytes", 0))
        baseline_rx_bytes = int(dashboard_stats.get("total_rx_bytes", 0))
        live_request = subprocess.Popen(
            [
                "curl",
                "--silent",
                "--show-error",
                "--fail",
                "--max-time",
                "20",
                "--output",
                os.devnull,
                "--socks5-hostname",
                f"127.0.0.1:{socks_port}",
                f"http://127.0.0.1:{slow_http_port}/stream",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            slow_http_server.wait_for_first_chunk(10)
            live_dashboard = None
            deadline = time.time() + 10
            while time.time() < deadline:
                candidate = fetch_json(f"http://127.0.0.1:{web_port}/api/traces/dashboard")
                candidate_stats = candidate.get("stats", {})
                if (
                    candidate_stats.get("running_sessions") == 1
                    and int(candidate_stats.get("total_tx_bytes", 0)) > baseline_tx_bytes
                    and int(candidate_stats.get("total_rx_bytes", 0)) > baseline_rx_bytes
                ):
                    live_dashboard = candidate
                    break
                time.sleep(0.2)
            if live_dashboard is None:
                raise RuntimeError("dashboard live traffic did not increase before session close")
        finally:
            live_stdout, live_stderr = live_request.communicate(timeout=20)
        if live_request.returncode != 0:
            raise RuntimeError(f"live curl failed stdout:\n{live_stdout}\nstderr:\n{live_stderr}")

        stats_after_live = fetch_json(f"http://127.0.0.1:{web_port}/api/traces/stats")
        if stats_after_live.get("total_sessions") != 2:
            raise RuntimeError(f"unexpected stats after live session total_sessions: {stats_after_live}")
        if stats_after_live.get("success_sessions") != 2:
            raise RuntimeError(f"unexpected stats after live session success_sessions: {stats_after_live}")
        if stats_after_live.get("running_sessions") != 0:
            raise RuntimeError(f"unexpected stats after live session running_sessions: {stats_after_live}")

        failed_port = allocate_tcp_port()
        failed_request = subprocess.run(
            [
                "curl",
                "--silent",
                "--show-error",
                "--max-time",
                "5",
                "--socks5-hostname",
                f"127.0.0.1:{socks_port}",
                f"http://127.0.0.1:{failed_port}/missing.txt",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        if failed_request.returncode == 0:
            raise RuntimeError("unexpected failing request succeeded")

        failed_item = None
        deadline = time.time() + 10
        while time.time() < deadline:
            failed_list = fetch_json(
                f"http://127.0.0.1:{web_port}/api/traces?status=failed&limit=10&sort_field=last_event_time&sort_order=desc"
            )
            for candidate in failed_list.get("items", []):
                if candidate.get("target_port") == failed_port:
                    failed_item = candidate
                    break
            if failed_item is not None:
                break
            time.sleep(0.2)
        if failed_item is None:
            raise RuntimeError("failed trace not recorded after connect error")
        if failed_item.get("status") != "failed":
            raise RuntimeError(f"unexpected failed trace status: {failed_item}")

        failed_trace_id = failed_item.get("trace_id")
        if not isinstance(failed_trace_id, str) or len(failed_trace_id) != 16:
            raise RuntimeError(f"unexpected failed trace_id: {failed_item}")

        failed_detail = fetch_json(f"http://127.0.0.1:{web_port}/api/traces/{failed_trace_id}")
        failed_summary = failed_detail.get("summary", {})
        if failed_summary.get("status") != "failed":
            raise RuntimeError(f"unexpected failed summary status: {failed_detail}")
        if failed_summary.get("target_port") != failed_port:
            raise RuntimeError(f"unexpected failed summary target_port: {failed_detail}")

        stats_after_failure = fetch_json(f"http://127.0.0.1:{web_port}/api/traces/stats")
        if stats_after_failure.get("total_sessions") != 3:
            raise RuntimeError(f"unexpected stats after failure total_sessions: {stats_after_failure}")
        if stats_after_failure.get("success_sessions") != 2:
            raise RuntimeError(f"unexpected stats after failure success_sessions: {stats_after_failure}")
        if stats_after_failure.get("failed_sessions") != 1:
            raise RuntimeError(f"unexpected stats after failure failed_sessions: {stats_after_failure}")

        dashboard_after_failure = fetch_json(f"http://127.0.0.1:{web_port}/api/traces/dashboard")
        if dashboard_after_failure.get("status_counts", {}).get("failed") != 1:
            raise RuntimeError(f"unexpected dashboard failed count: {dashboard_after_failure}")

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
        if slow_http_server is not None:
            try:
                slow_http_server.terminate()
            except Exception:
                pass
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
