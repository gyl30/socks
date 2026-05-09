#!/usr/bin/env python3

import argparse
import http.server
import json
import shutil
import signal
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from testlib import (
    allocate_tcp_port,
    build_cert,
    build_runtime_env,
    make_reality_client_config,
    make_reality_server_config,
    parse_key_output,
    run_checked,
    save_json,
    start_process,
    tail_file,
    wait_for_log_text,
    wait_for_port,
)


def stop_processes(processes):
    for process in reversed(processes):
        try:
            process.terminate()
        except Exception:
            pass


class large_https_handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "vision-load/1.0"

    def do_GET(self):
        body_bytes = self.server.body_bytes
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(body_bytes))
        self.send_header("Connection", "close")
        self.end_headers()

        chunk = self.server.chunk
        remaining = body_bytes
        while remaining > 0:
            piece = chunk if remaining >= len(chunk) else chunk[:remaining]
            self.wfile.write(piece)
            remaining -= len(piece)

    def log_message(self, _format, *_args):
        return


class threaded_https_server(http.server.ThreadingHTTPServer):
    daemon_threads = True


class https_origin_server:
    def __init__(self, cert_path, key_path, body_bytes):
        self.port = allocate_tcp_port()
        self.server = threaded_https_server(("127.0.0.1", self.port), large_https_handler)
        self.server.body_bytes = body_bytes
        self.server.chunk = b"x" * 65536
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def start_stack(repo_root, binary, runtime_env, temp_root, *, server_vision, client_vision, body_bytes):
    server_port = allocate_tcp_port()
    socks_port = allocate_tcp_port()
    key_output = run_checked([str(binary), "x25519"], env=runtime_env, capture_output=True)
    private_key, public_key = parse_key_output(key_output.stdout)
    key_path, cert_path = build_cert(temp_root, "localhost")
    origin = https_origin_server(cert_path, key_path, body_bytes)

    server_log = temp_root / "server.log"
    client_log = temp_root / "client.log"

    server_cfg = make_reality_server_config(
        log_file=server_log,
        port=server_port,
        sni="vision.test",
        private_key=private_key,
        public_key=public_key,
        vision=server_vision,
    )
    server_cfg["inbounds"][0]["settings"]["fetch_site_material"] = False

    client_cfg = make_reality_client_config(
        log_file=client_log,
        socks_port=socks_port,
        server_port=server_port,
        sni="vision.test",
        public_key=public_key,
        vision=client_vision,
    )

    server_config_path = temp_root / "server.json"
    client_config_path = temp_root / "client.json"
    save_json(server_config_path, server_cfg)
    save_json(client_config_path, client_cfg)

    server_process = start_process([str(binary), "-c", str(server_config_path)], str(server_log), extra_env=runtime_env)
    client_process = start_process([str(binary), "-c", str(client_config_path)], str(client_log), extra_env=runtime_env)
    processes = [server_process, client_process]

    wait_for_log_text(server_log, f"listen 127.0.0.1:{server_port} reality inbound listening", 20, "vision load server log", processes)
    wait_for_log_text(client_log, f"listen 127.0.0.1:{socks_port} socks listening", 20, "vision load client log", processes)
    wait_for_port("127.0.0.1", socks_port, 20, "vision load socks proxy", processes)

    return {
        "origin": origin,
        "cert_path": cert_path,
        "origin_port": origin.port,
        "socks_port": socks_port,
        "server_log": server_log,
        "client_log": client_log,
        "server_process": server_process,
        "client_process": client_process,
        "processes": processes,
    }


def start_resource_monitor(repo_root, stack, output_path):
    return subprocess.Popen(
        [
            sys.executable,
            str(repo_root / "scripts/process_resource_monitor.py"),
            "--pid",
            f"server:{stack['server_process'].process.pid}",
            "--pid",
            f"client:{stack['client_process'].process.pid}",
            "--interval-ms",
            "50",
            "--output",
            str(output_path),
        ]
    )


def stop_resource_monitor(process, output_path):
    process.send_signal(signal.SIGINT)
    process.wait(timeout=10)
    with open(output_path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def run_curl_request(stack, tls_version, body_bytes):
    if tls_version == "1.3":
        tls_args = ["--tlsv1.3", "--tls-max", "1.3"]
    else:
        tls_args = ["--tlsv1.2", "--tls-max", "1.2"]

    args = [
        "curl",
        "--silent",
        "--show-error",
        "--fail",
        "--ipv4",
        *tls_args,
        "--connect-timeout",
        "5",
        "--max-time",
        "60",
        "--proxy",
        f"socks5://127.0.0.1:{stack['socks_port']}",
        "--cacert",
        str(stack["cert_path"]),
        "--output",
        "/dev/null",
        "--write-out",
        "size_download=%{size_download}\n",
        f"https://localhost:{stack['origin_port']}/load?size={body_bytes}",
    ]
    result = subprocess.run(args, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"curl failed rc={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}")

    for line in result.stdout.splitlines():
        if line.startswith("size_download="):
            downloaded = int(float(line.split("=", 1)[1]))
            if downloaded != body_bytes:
                raise RuntimeError(f"curl downloaded unexpected bytes downloaded={downloaded} expected={body_bytes}")
            return downloaded

    raise RuntimeError(f"curl output missing size_download {result.stdout!r}")


def run_parallel_load(stack, tls_version, body_bytes, concurrency, requests_per_worker):
    total_requests = concurrency * requests_per_worker

    def one_request(_index):
        return run_curl_request(stack, tls_version, body_bytes)

    started_at = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        results = list(executor.map(one_request, range(total_requests)))
    duration = time.perf_counter() - started_at
    total_bytes = sum(results)
    throughput_mib_per_s = (total_bytes / (1024.0 * 1024.0)) / duration if duration > 0 else 0.0

    return {
        "requests": total_requests,
        "total_bytes": total_bytes,
        "duration_seconds": duration,
        "throughput_mib_per_s": throughput_mib_per_s,
    }


def summarize_resources(resource_summary):
    summarized = {}
    for label in ("server", "client"):
        proc = resource_summary["processes"][label]
        summarized[label] = {
            "peak_rss_mib": proc["peak_rss_kb"] / 1024.0,
            "cpu_seconds_total": proc["cpu_seconds_total"],
            "sample_count": proc["sample_count"],
        }
    return summarized


def assert_direct_mode(stack, expect_direct):
    merged = (
        stack["server_log"].read_text(encoding="utf-8", errors="replace")
        + "\n"
        + stack["client_log"].read_text(encoding="utf-8", errors="replace")
    )
    direct_seen = "enter_raw_write_mode" in merged or "enter_raw_read_mode" in merged
    if expect_direct and not direct_seen:
        raise RuntimeError("expected direct mode logs but did not see them")
    if not expect_direct and direct_seen:
        raise RuntimeError("unexpected direct mode logs in fallback scenario")


def assert_resource_bounds(summary):
    for label in ("server", "client"):
        proc = summary[label]
        if proc["sample_count"] < 2:
            raise RuntimeError(f"{label} resource sample count too small")
        if proc["peak_rss_mib"] > 256.0:
            raise RuntimeError(f"{label} peak rss too large rss_mib={proc['peak_rss_mib']:.2f}")


def main():
    parser = argparse.ArgumentParser(description="Reality Vision concurrent load regression")
    parser.add_argument("--binary", default=str(Path("build") / "socks"))
    parser.add_argument("--body-bytes", type=int, default=4 * 1024 * 1024)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--requests-per-worker", type=int, default=2)
    parser.add_argument("--keep-artifacts", action="store_true")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    binary = Path(args.binary)
    if not binary.is_absolute():
        binary = (repo_root / binary).resolve()
    if not binary.is_file():
        raise RuntimeError(f"binary not found: {binary}")
    for command_name in ("curl", "openssl"):
        if shutil.which(command_name) is None:
            raise RuntimeError(f"missing dependency: {command_name}")

    runtime_env = build_runtime_env(binary)
    temp_root = Path(tempfile.mkdtemp(prefix=".tmp-reality-vision-load.", dir=repo_root))
    results = {}
    active_processes = []
    active_origin = None
    active_monitor = None
    active_monitor_path = None

    scenarios = [
        ("vision_tls13_direct", True, True, "1.3", True),
        ("vision_tls12_fallback", True, True, "1.2", False),
        ("reality_tls13_baseline", False, False, "1.3", False),
    ]

    try:
        for name, server_vision, client_vision, tls_version, expect_direct in scenarios:
            scenario_root = temp_root / name
            scenario_root.mkdir(parents=True, exist_ok=True)
            stack = start_stack(
                repo_root,
                binary,
                runtime_env,
                scenario_root,
                server_vision=server_vision,
                client_vision=client_vision,
                body_bytes=args.body_bytes,
            )
            active_processes = stack["processes"]
            active_origin = stack["origin"]
            active_monitor_path = scenario_root / "resource-summary.json"
            active_monitor = start_resource_monitor(repo_root, stack, active_monitor_path)

            try:
                load_summary = run_parallel_load(
                    stack,
                    tls_version,
                    args.body_bytes,
                    args.concurrency,
                    args.requests_per_worker,
                )
                assert_direct_mode(stack, expect_direct)
            finally:
                resource_summary = stop_resource_monitor(active_monitor, active_monitor_path)
                active_monitor = None
                stop_processes(active_processes)
                active_processes = []
                active_origin.close()
                active_origin = None

            resources = summarize_resources(resource_summary)
            assert_resource_bounds(resources)
            results[name] = {
                "load": load_summary,
                "resources": resources,
                "artifacts": str(scenario_root),
            }

        baseline = results["reality_tls13_baseline"]["load"]["throughput_mib_per_s"]
        if baseline <= 0.0:
            raise RuntimeError("baseline throughput must be positive")

        for name in ("vision_tls13_direct", "vision_tls12_fallback"):
            throughput = results[name]["load"]["throughput_mib_per_s"]
            if throughput < baseline * 0.6:
                raise RuntimeError(
                    f"{name} throughput regressed too much throughput={throughput:.2f} baseline={baseline:.2f}"
                )

        summary_path = temp_root / "summary.json"
        save_json(summary_path, results)
        print(json.dumps(results, ensure_ascii=False, indent=2))
        print(f"summary_path={summary_path}")
        return 0
    except Exception as exc:
        print(f"vision load regression failed {exc}", file=sys.stderr)
        for log_path in temp_root.glob("**/*.log"):
            print(f"===== {log_path.relative_to(temp_root)} =====", file=sys.stderr)
            print(tail_file(log_path), file=sys.stderr)
        raise
    finally:
        if active_monitor is not None and active_monitor.poll() is None and active_monitor_path is not None:
            stop_resource_monitor(active_monitor, active_monitor_path)
        stop_processes(active_processes)
        if active_origin is not None:
            active_origin.close()
        if args.keep_artifacts:
            print(f"artifacts kept at {temp_root}", file=sys.stderr)
        else:
            subprocess.run(["rm", "-rf", str(temp_root)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    raise SystemExit(main())
