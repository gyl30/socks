#!/usr/bin/env python3

import argparse
import json
import os
import pathlib
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time


class ProcessManager:
    def __init__(self):
        self.processes = []

    def start(self, args, stdout_path):
        stdout_handle = open(stdout_path, "w", encoding="utf-8")
        process = subprocess.Popen(args, stdout=stdout_handle, stderr=subprocess.STDOUT, text=True)
        self.processes.append((process, stdout_handle))
        return process

    def terminate_all(self):
        for process, _stdout_handle in reversed(self.processes):
            if process.poll() is None:
                process.terminate()
        for process, stdout_handle in reversed(self.processes):
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            stdout_handle.close()


def allocate_tcp_ports(count):
    sockets = []
    ports = []
    for _ in range(count):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        sockets.append(sock)
        ports.append(sock.getsockname()[1])
    for sock in sockets:
        sock.close()
    return ports


def parse_key_output(output):
    private_match = re.search(r"private key:\s+(\S+)", output)
    public_match = re.search(r"public key:\s+(\S+)", output)
    if private_match is None or public_match is None:
        raise RuntimeError("failed to parse x25519 key output")
    return private_match.group(1), public_match.group(1)


def write_json(path, data):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


def wait_for_port(host, port, process, name):
    deadline = time.time() + 10.0
    while time.time() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"{name} exited early")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.2)
        try:
            sock.connect((host, port))
            return
        except OSError:
            time.sleep(0.1)
        finally:
            sock.close()
    raise RuntimeError(f"timeout waiting for {name} {host}:{port}")


def run_command(args, cwd):
    result = subprocess.run(args, cwd=cwd, text=True, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed {' '.join(args)}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result.stdout


def parse_summary_lines(text):
    summary = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        summary[key.strip()] = value.strip()
    return summary


def read_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def count_log_occurrences(path, keyword):
    with open(path, "r", encoding="utf-8") as handle:
        return sum(1 for line in handle if keyword in line)


def count_idle_events(tmp_dir):
    return (
        count_log_occurrences(tmp_dir / "client.log", "upstream_to_client read failed Connection timed out")
        + count_log_occurrences(tmp_dir / "client.log", "tcp session idle closing")
        + count_log_occurrences(tmp_dir / "server.log", "mux upstream stream read finished Connection timed out")
        + count_log_occurrences(tmp_dir / "server.log", "timeout idle timeout")
    )


def build_server_config(tmp_dir, server_port, private_key, public_key, short_id, sni, workers, timeouts, limits):
    return {
        "mode": "server",
        "workers": workers,
        "log": {
            "level": "debug",
            "file": str(tmp_dir / "server.log"),
        },
        "inbound": {
            "host": "127.0.0.1",
            "port": server_port,
        },
        "socks": {
            "enabled": False,
        },
        "reality": {
            "sni": sni,
            "private_key": private_key,
            "public_key": public_key,
            "short_id": short_id,
        },
        "timeout": timeouts,
        "limits": limits,
    }


def build_client_config(tmp_dir, socks_port, server_port, public_key, short_id, sni, workers, timeouts, limits):
    return {
        "mode": "client",
        "workers": workers,
        "log": {
            "level": "debug",
            "file": str(tmp_dir / "client.log"),
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
            "sni": sni,
            "fingerprint": "random",
            "public_key": public_key,
            "short_id": short_id,
        },
        "timeout": timeouts,
        "limits": limits,
        "heartbeat": {
            "enabled": True,
            "min_interval": 4,
            "max_interval": 6,
            "min_padding": 32,
            "max_padding": 64,
        },
    }


def print_resource_summary(resource_summary):
    for label in ("client", "server"):
        proc = resource_summary["processes"][label]
        print(
            f"{label} peak_rss_kb={proc['peak_rss_kb']} "
            f"peak_fd_count={proc['peak_fd_count']} "
            f"peak_threads={proc['peak_threads']} "
            f"cpu_seconds_total={proc['cpu_seconds_total']:.3f}"
        )


def tail_logs(tmp_dir):
    for log_file in sorted(tmp_dir.glob("*.log")):
        print(f"===== {log_file.name} =====", file=sys.stderr)
        try:
            with open(log_file, "r", encoding="utf-8") as handle:
                lines = handle.readlines()[-80:]
        except FileNotFoundError:
            continue
        for line in lines:
            sys.stderr.write(line)


def create_environment(repo_root, binary, mode_name):
    tmp_dir = pathlib.Path(tempfile.mkdtemp(prefix=f".tmp-socks5-{mode_name}.", dir=repo_root))
    server_port, socks_port, http_port = allocate_tcp_ports(3)
    key_output = run_command([str(binary), "x25519"], cwd=repo_root)
    private_key, public_key = parse_key_output(key_output)
    short_id = "0102030405060708"
    sni = "www.example.com"

    if mode_name == "long":
        workers = 2
        timeouts = {"read": 2, "write": 2, "connect": 3, "idle": 3}
        limits = {"max_connections": 32, "max_buffer": 33554432, "max_streams": 2048, "max_handshake_records": 256}
    else:
        workers = 4
        timeouts = {"read": 2, "write": 2, "connect": 3, "idle": 3}
        limits = {"max_connections": 128, "max_buffer": 33554432, "max_streams": 4096, "max_handshake_records": 256}

    server_config = build_server_config(tmp_dir, server_port, private_key, public_key, short_id, sni, workers, timeouts, limits)
    client_config = build_client_config(tmp_dir, socks_port, server_port, public_key, short_id, sni, workers, timeouts, limits)
    write_json(tmp_dir / "server.json", server_config)
    write_json(tmp_dir / "client.json", client_config)

    manager = ProcessManager()
    http_process = manager.start(
        [sys.executable, str(repo_root / "scripts/slow_http_server.py"), "--host", "127.0.0.1", "--port", str(http_port)],
        tmp_dir / "http.log",
    )
    server_process = manager.start([str(binary), "-c", str(tmp_dir / "server.json")], tmp_dir / "server.stdout.log")
    client_process = manager.start([str(binary), "-c", str(tmp_dir / "client.json")], tmp_dir / "client.stdout.log")

    wait_for_port("127.0.0.1", http_port, http_process, "slow_http_server")
    wait_for_port("127.0.0.1", server_port, server_process, "reality_server")
    wait_for_port("127.0.0.1", socks_port, client_process, "socks5_listener")

    monitor_path = tmp_dir / "resource-summary.json"
    monitor_process = manager.start(
        [
            sys.executable,
            str(repo_root / "scripts/process_resource_monitor.py"),
            "--pid",
            f"client:{client_process.pid}",
            "--pid",
            f"server:{server_process.pid}",
            "--interval-ms",
            "100",
            "--output",
            str(monitor_path),
        ],
        tmp_dir / "resource-monitor.log",
    )

    return {
        "tmp_dir": tmp_dir,
        "server_port": server_port,
        "socks_port": socks_port,
        "http_port": http_port,
        "manager": manager,
        "client_process": client_process,
        "server_process": server_process,
        "monitor_process": monitor_process,
        "monitor_path": monitor_path,
    }


def finalize_environment(env):
    if env["monitor_process"].poll() is None:
        env["monitor_process"].terminate()
        try:
            env["monitor_process"].wait(timeout=5)
        except subprocess.TimeoutExpired:
            env["monitor_process"].kill()
            env["monitor_process"].wait(timeout=5)
    env["manager"].terminate_all()


def run_client_case(repo_root, env, mode, path, expect_failure=False, overall_timeout=0, stall_seconds=0, recv_buffer=0):
    args = [
        sys.executable,
        str(repo_root / "scripts/socks5_http_case_client.py"),
        "--mode",
        mode,
        "--socks-host",
        "127.0.0.1",
        "--socks-port",
        str(env["socks_port"]),
        "--target-host",
        "127.0.0.1",
        "--target-port",
        str(env["http_port"]),
        "--path",
        path,
    ]
    if expect_failure:
        args.append("--expect-failure")
    if overall_timeout > 0:
        args.extend(["--overall-timeout", str(overall_timeout)])
    if stall_seconds > 0:
        args.extend(["--stall-seconds", str(stall_seconds)])
    if recv_buffer > 0:
        args.extend(["--recv-buffer", str(recv_buffer)])
    return run_command(args, cwd=repo_root)


def run_handshake_stall(repo_root, env, count, stage, stall_seconds):
    args = [
        sys.executable,
        str(repo_root / "scripts/socks5_http_case_client.py"),
        "--mode",
        "handshake-stall",
        "--socks-host",
        "127.0.0.1",
        "--socks-port",
        str(env["socks_port"]),
        "--count",
        str(count),
        "--stage",
        stage,
        "--stall-seconds",
        str(stall_seconds),
    ]
    return run_command(args, cwd=repo_root)


def run_parallel_failure_cases(repo_root, env, count, path, overall_timeout):
    processes = []
    outputs = []
    for _ in range(count):
        args = [
            sys.executable,
            str(repo_root / "scripts/socks5_http_case_client.py"),
            "--mode",
            "read-full",
            "--socks-host",
            "127.0.0.1",
            "--socks-port",
            str(env["socks_port"]),
            "--target-host",
            "127.0.0.1",
            "--target-port",
            str(env["http_port"]),
            "--path",
            path,
            "--expect-failure",
            "--overall-timeout",
            str(overall_timeout),
        ]
        processes.append(subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=repo_root))

    for process in processes:
        output, _ = process.communicate()
        if process.returncode != 0:
            raise RuntimeError(f"parallel failure case returned {process.returncode}\n{output}")
        outputs.append(output.strip())
    return outputs


def run_long_mode(repo_root, binary, keep_artifacts):
    env = create_environment(repo_root, binary, "long")
    tmp_dir = env["tmp_dir"]
    try:
        print("== 长连接/慢速传输 ==")
        load_output = run_command(
            [
                sys.executable,
                str(repo_root / "scripts/socks5_tcp_load.py"),
                "--socks-host",
                "127.0.0.1",
                "--socks-port",
                str(env["socks_port"]),
                "--target-host",
                "127.0.0.1",
                "--target-port",
                str(env["http_port"]),
                "--path",
                "/slow-success?body_bytes=65536&chunk_size=4096&chunk_interval_ms=50&header_delay_ms=500",
                "--concurrency",
                "8",
                "--requests-per-worker",
                "1",
            ],
            cwd=repo_root,
        )
        print(load_output.strip())

        before_idle = count_idle_events(tmp_dir)
        print(run_client_case(repo_root, env, "read-full", "/stall-before-header?delay_ms=4500&body_bytes=2048", True, 8).strip())
        print(run_client_case(repo_root, env, "read-full", "/stall-mid-body?body_bytes=32768&first_chunk_bytes=2048&stall_ms=4500", True, 8).strip())
        time.sleep(1.0)
        after_idle = count_idle_events(tmp_dir)
        idle_hits = after_idle - before_idle
        if idle_hits < 2:
            raise RuntimeError(f"expected at least 2 idle timeout hits got {idle_hits}")

        before_write_timeout = count_log_occurrences(tmp_dir / "client.log", "upstream_to_client write failed")
        print(
            run_client_case(
                repo_root,
                env,
                "send-and-stall",
                "/fast-large?body_bytes=268435456&chunk_size=65536&chunk_interval_ms=0",
                False,
                12,
                6,
                1024,
            ).strip()
        )
        time.sleep(1.5)
        after_write_timeout = count_log_occurrences(tmp_dir / "client.log", "upstream_to_client write failed")
        write_timeout_hits = after_write_timeout - before_write_timeout
        if write_timeout_hits < 1:
            raise RuntimeError("expected at least 1 write timeout hit")

        finalize_environment(env)
        resource_summary = read_json(env["monitor_path"])
        load_summary = parse_summary_lines(load_output)
        print(f"idle_timeout_hits={idle_hits}")
        print(f"write_timeout_hits={write_timeout_hits}")
        print(f"slow_success_connections={load_summary.get('connections', '0')}")
        print_resource_summary(resource_summary)
    except Exception:
        finalize_environment(env)
        tail_logs(tmp_dir)
        print(f"long mode artifacts kept at {tmp_dir}", file=sys.stderr)
        raise
    else:
        if keep_artifacts:
            print(f"long mode artifacts kept at {tmp_dir}")
        else:
            shutil.rmtree(tmp_dir)


def run_churn_mode(repo_root, binary, keep_artifacts):
    env = create_environment(repo_root, binary, "churn")
    tmp_dir = env["tmp_dir"]
    try:
        print("== 短连接/高 churn ==")
        load_output = run_command(
            [
                sys.executable,
                str(repo_root / "scripts/socks5_tcp_load.py"),
                "--socks-host",
                "127.0.0.1",
                "--socks-port",
                str(env["socks_port"]),
                "--target-host",
                "127.0.0.1",
                "--target-port",
                str(env["http_port"]),
                "--path",
                "/fast-large?body_bytes=2048&chunk_size=2048&chunk_interval_ms=0",
                "--concurrency",
                "64",
                "--requests-per-worker",
                "12",
            ],
            cwd=repo_root,
        )
        print(load_output.strip())

        before_handshake_timeout = count_log_occurrences(tmp_dir / "client.log", "handshake failed Connection timed out")
        print(run_handshake_stall(repo_root, env, 64, "greeting-header", 3).strip())
        time.sleep(1.0)
        after_handshake_timeout = count_log_occurrences(tmp_dir / "client.log", "handshake failed Connection timed out")
        handshake_timeout_hits = after_handshake_timeout - before_handshake_timeout
        if handshake_timeout_hits < 32:
            raise RuntimeError(f"expected at least 32 handshake timeouts got {handshake_timeout_hits}")

        before_idle = count_idle_events(tmp_dir)
        outputs = run_parallel_failure_cases(
            repo_root,
            env,
            24,
            "/stall-before-header?delay_ms=4500&body_bytes=1024",
            8,
        )
        for output in outputs[:3]:
            print(output)
        time.sleep(1.0)
        after_idle = count_idle_events(tmp_dir)
        idle_hits = after_idle - before_idle
        if idle_hits < 12:
            raise RuntimeError(f"expected at least 12 idle timeout hits got {idle_hits}")

        finalize_environment(env)
        resource_summary = read_json(env["monitor_path"])
        load_summary = parse_summary_lines(load_output)
        print(f"handshake_timeout_hits={handshake_timeout_hits}")
        print(f"idle_timeout_hits={idle_hits}")
        print(f"churn_success_connections={load_summary.get('connections', '0')}")
        print_resource_summary(resource_summary)
    except Exception:
        finalize_environment(env)
        tail_logs(tmp_dir)
        print(f"churn mode artifacts kept at {tmp_dir}", file=sys.stderr)
        raise
    else:
        if keep_artifacts:
            print(f"churn mode artifacts kept at {tmp_dir}")
        else:
            shutil.rmtree(tmp_dir)


def main():
    parser = argparse.ArgumentParser(description="SOCKS5 resource and timeout test suite")
    parser.add_argument("--mode", choices=["long", "churn", "all"], required=True)
    parser.add_argument("--binary", default="")
    parser.add_argument("--keep-artifacts", action="store_true")
    args = parser.parse_args()

    repo_root = pathlib.Path(__file__).resolve().parent.parent
    binary = pathlib.Path(args.binary) if args.binary else repo_root / "build-review/socks"
    if not binary.is_file():
        raise RuntimeError(f"binary not found {binary}")

    if args.mode in ("long", "all"):
        run_long_mode(repo_root, binary, args.keep_artifacts)
    if args.mode in ("churn", "all"):
        run_churn_mode(repo_root, binary, args.keep_artifacts)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
