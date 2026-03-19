#!/usr/bin/env python3

import argparse
import json
import os
import pathlib
import re
import shutil
import socket
import statistics
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


def parse_key_output(output):
    private_match = re.search(r"private key:\s+(\S+)", output)
    public_match = re.search(r"public key:\s+(\S+)", output)
    if private_match is None or public_match is None:
        raise RuntimeError("failed to parse x25519 key output")
    return private_match.group(1), public_match.group(1)


def save_json(path, value):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2)
        handle.write("\n")


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
        ],
        capture_output=True,
    )
    return key_path, cert_path


def start_origin_services(repo_root, temp_root, https_port, http_port):
    https_log = temp_root / "origin-https.log"
    http_log = temp_root / "origin-http.log"
    key_path, cert_path = build_cert(temp_root, "localhost")

    origin_https = ManagedProcess(
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
    origin_http = ManagedProcess(
        [
            sys.executable,
            str(repo_root / "scripts/slow_http_server.py"),
            "--host",
            "127.0.0.1",
            "--port",
            str(http_port),
        ],
        str(http_log),
    )
    wait_for_log_text(https_log, f"ready 127.0.0.1:{https_port}", 10, "origin https log")
    wait_for_port("127.0.0.1", http_port, 10, "origin http server")
    return {
        "https": origin_https,
        "http": origin_http,
        "cert_path": cert_path,
        "key_path": key_path,
        "https_log": https_log,
        "http_log": http_log,
    }


def start_client_server_pair(repo_root, temp_root, binary, socks_port, server_port, fingerprint, server_log, client_log):
    private_key = None
    public_key = None
    key_output = run_checked([str(binary), "x25519"], capture_output=True)
    private_key, public_key = parse_key_output(key_output.stdout)
    reality_sni = "www.example.com"

    server_cfg = {
        "mode": "server",
        "workers": 1,
        "log": {
            "level": "info",
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
            "level": "info",
            "file": str(client_log),
        },
        "socks": {
            "enabled": True,
            "host": "127.0.0.1",
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
            "fingerprint": fingerprint,
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
            "max_connections": 32,
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

    save_json(temp_root / f"server-{fingerprint}.json", server_cfg)
    save_json(temp_root / f"client-{fingerprint}.json", client_cfg)

    server_process = ManagedProcess([str(binary), "-c", str(temp_root / f"server-{fingerprint}.json")], str(server_log))
    client_process = ManagedProcess([str(binary), "-c", str(temp_root / f"client-{fingerprint}.json")], str(client_log))
    wait_for_log_text(server_log, "remote server listening for connections", 20, "server log")
    wait_for_log_text(client_log, f"local socks5 listening on 127.0.0.1:{socks_port}", 20, "client log")
    wait_for_port("127.0.0.1", socks_port, 20, "socks5 proxy")
    return {
        "server": server_process,
        "client": client_process,
    }
def run_http_load_through_proxy(repo_root, proxy_port, target_port, body_bytes, concurrency):
    path = f"/fast-large?body_bytes={body_bytes}&chunk_size=65536"
    result = run_checked(
        [
            sys.executable,
            str(repo_root / "scripts/socks5_tcp_load.py"),
            "--socks-host",
            "127.0.0.1",
            "--socks-port",
            str(proxy_port),
            "--target-host",
            "127.0.0.1",
            "--target-port",
            str(target_port),
            "--path",
            path,
            "--concurrency",
            str(concurrency),
            "--requests-per-worker",
            "1",
        ],
        capture_output=True,
    )
    metrics = {}
    for line in result.stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        metrics[key.strip()] = value.strip()
    if "throughput_mib_per_s" not in metrics:
        raise RuntimeError(f"missing throughput metric in output {result.stdout!r}")
    throughput_mib_per_s = float(metrics["throughput_mib_per_s"])
    total_bytes = int(metrics.get("bytes", "0"))
    return {
        "bytes": total_bytes,
        "mib_per_second": throughput_mib_per_s,
        "raw": result.stdout.strip(),
    }


def measure_ttfb(proxy_port, cert_path, https_port, samples):
    proxy_url = f"socks5h://127.0.0.1:{proxy_port}"
    target_url = f"https://localhost:{https_port}/healthz.txt"

    run_checked(
        [
            "curl",
            "--silent",
            "--show-error",
            "--fail",
            "--proxy",
            proxy_url,
            "--cacert",
            str(cert_path),
            target_url,
            "-o",
            "/dev/null",
        ],
        capture_output=True,
    )

    ttfb_ms = []
    total_ms = []
    for _ in range(samples):
        result = run_checked(
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
                "-w",
                "%{time_starttransfer} %{time_total}\n",
                "-o",
                "/dev/null",
                target_url,
            ],
            capture_output=True,
        )
        values = result.stdout.strip().split()
        if len(values) != 2:
            raise RuntimeError(f"unexpected curl timing output {result.stdout!r}")
        ttfb_ms.append(float(values[0]) * 1000.0)
        total_ms.append(float(values[1]) * 1000.0)

    return {
        "samples": samples,
        "ttfb_ms": ttfb_ms,
        "total_ms": total_ms,
        "ttfb_median_ms": statistics.median(ttfb_ms),
        "ttfb_mean_ms": statistics.mean(ttfb_ms),
        "total_median_ms": statistics.median(total_ms),
        "total_mean_ms": statistics.mean(total_ms),
    }


def run_profile(
    repo_root,
    temp_root,
    binary,
    shared,
    profile_name,
    fingerprint,
    ttfb_samples,
    throughput_body_bytes,
    throughput_concurrency,
):
    profile_root = temp_root / profile_name
    profile_root.mkdir(parents=True, exist_ok=True)
    server_log = profile_root / "server.log"
    client_log = profile_root / "client.log"
    monitor_log = profile_root / "monitor.log"
    resource_json = profile_root / "resource-summary.json"
    socks_port = allocate_tcp_port()
    server_port = allocate_tcp_port()

    processes = []
    pair = None
    monitor = None
    try:
        pair = start_client_server_pair(repo_root, profile_root, binary, socks_port, server_port, fingerprint, server_log, client_log)
        processes.extend([pair["server"], pair["client"]])
        monitor = ManagedProcess(
            [
                sys.executable,
                str(repo_root / "scripts/process_resource_monitor.py"),
                "--pid",
                f"server:{pair['server'].process.pid}",
                "--pid",
                f"client:{pair['client'].process.pid}",
                "--interval-ms",
                "100",
                "--output",
                str(resource_json),
            ],
            str(monitor_log),
        )
        processes.append(monitor)
        single = run_http_load_through_proxy(repo_root, socks_port, shared["http_port"], throughput_body_bytes, 1)
        multi = run_http_load_through_proxy(repo_root, socks_port, shared["http_port"], throughput_body_bytes, throughput_concurrency)
        ttfb = measure_ttfb(socks_port, shared["cert_path"], shared["https_port"], ttfb_samples)
    finally:
        for process in reversed(processes):
            try:
                process.terminate()
            except Exception:
                pass

    resource_summary = json.loads(resource_json.read_text(encoding="utf-8"))
    server_proc = resource_summary["processes"]["server"]
    client_proc = resource_summary["processes"]["client"]

    return {
        "single": single,
        "multi": multi,
        "ttfb": ttfb,
        "resources": {
            "server": server_proc,
            "client": client_proc,
        },
        "logs": {
            "server": tail_file(server_log),
            "client": tail_file(client_log),
            "monitor": tail_file(monitor_log),
        },
    }


def print_profile_summary(name, result):
    server_proc = result["resources"]["server"]
    client_proc = result["resources"]["client"]
    print(f"profile={name}")
    print(f"  throughput_single_mib_per_s={result['single']['mib_per_second']:.2f}")
    print(f"  throughput_multi_mib_per_s={result['multi']['mib_per_second']:.2f}")
    print(f"  ttfb_median_ms={result['ttfb']['ttfb_median_ms']:.2f}")
    print(f"  ttfb_mean_ms={result['ttfb']['ttfb_mean_ms']:.2f}")
    print(f"  total_median_ms={result['ttfb']['total_median_ms']:.2f}")
    print(f"  server_peak_rss_kb={server_proc['peak_rss_kb']}")
    print(f"  server_cpu_seconds_total={server_proc['cpu_seconds_total']:.3f}")
    print(f"  client_peak_rss_kb={client_proc['peak_rss_kb']}")
    print(f"  client_cpu_seconds_total={client_proc['cpu_seconds_total']:.3f}")


def main():
    parser = argparse.ArgumentParser(description="Reality benchmark for throughput, TTFB, and resource usage")
    parser.add_argument("--binary", default=str(pathlib.Path("build") / "socks"), help="path to the socks binary")
    parser.add_argument("--ttfb-samples", type=int, default=5)
    parser.add_argument("--throughput-body-bytes", type=int, default=16 * 1024 * 1024)
    parser.add_argument("--throughput-concurrency", type=int, default=4)
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--json-output", default="")
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

    temp_root = pathlib.Path(tempfile.mkdtemp(prefix=".tmp-reality-benchmark.", dir=repo_root))
    cleanup_processes = []
    try:
        https_port = allocate_tcp_port()
        http_port = allocate_tcp_port()

        shared = {
            "https_port": https_port,
            "http_port": http_port,
        }

        shared_dir = temp_root / "shared"
        shared_dir.mkdir(parents=True, exist_ok=True)
        origin = start_origin_services(repo_root, shared_dir, https_port, http_port)
        cleanup_processes.extend([origin["http"], origin["https"]])
        shared["cert_path"] = origin["cert_path"]
        shared["https_log"] = origin["https_log"]
        shared["http_log"] = origin["http_log"]

        profiles = [
            ("x25519", "chrome"),
            ("mlkem768", "chrome_mlkem768"),
        ]
        results = {}
        for profile_name, fingerprint in profiles:
            results[profile_name] = run_profile(
                repo_root,
                temp_root,
                binary,
                shared,
                profile_name,
                fingerprint,
                args.ttfb_samples,
                args.throughput_body_bytes,
                args.throughput_concurrency,
            )
            print_profile_summary(profile_name, results[profile_name])

        ttfb_delta_ms = results["mlkem768"]["ttfb"]["ttfb_median_ms"] - results["x25519"]["ttfb"]["ttfb_median_ms"]
        throughput_single_delta = results["mlkem768"]["single"]["mib_per_second"] - results["x25519"]["single"]["mib_per_second"]
        throughput_multi_delta = results["mlkem768"]["multi"]["mib_per_second"] - results["x25519"]["multi"]["mib_per_second"]

        print(f"ttfb_delta_ms={ttfb_delta_ms:.2f}")
        print(f"throughput_single_delta_mib_per_s={throughput_single_delta:.2f}")
        print(f"throughput_multi_delta_mib_per_s={throughput_multi_delta:.2f}")

        summary = {
            "profiles": results,
            "deltas": {
                "ttfb_median_ms": ttfb_delta_ms,
                "throughput_single_mib_per_s": throughput_single_delta,
                "throughput_multi_mib_per_s": throughput_multi_delta,
            },
        }
        if args.json_output:
            json_output_path = pathlib.Path(args.json_output)
            if not json_output_path.is_absolute():
                json_output_path = (repo_root / json_output_path).resolve()
            json_output_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        return 0
    except Exception as exc:
        print(f"benchmark failed {exc}", file=sys.stderr)
        raise
    finally:
        for process in reversed(cleanup_processes):
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
