#!/usr/bin/env python3

import argparse
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

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


def wait_for_any_log_text(paths, needle, deadline_seconds, label, processes):
    deadline = time.time() + deadline_seconds
    while time.time() < deadline:
        for process in processes:
            if process.process.poll() is not None:
                raise RuntimeError(f"process exited early while waiting for {label}")
        for path in paths:
            if path.exists() and needle in path.read_text(encoding="utf-8", errors="replace"):
                return
        time.sleep(0.2)
    tails = "\n".join(f"===== {path.name} =====\n{tail_file(path)}" for path in paths)
    raise RuntimeError(f"timeout waiting for {label} log text {needle!r}\n{tails}")


def run_curl_through_socks(socks_port, cert_path, https_port, expect_success):
    args = [
        "curl",
        "--silent",
        "--show-error",
        "--fail",
        "--ipv4",
        "--tlsv1.3",
        "--tls-max",
        "1.3",
        "--connect-timeout",
        "5",
        "--max-time",
        "20",
        "--proxy",
        f"socks5://127.0.0.1:{socks_port}",
        "--cacert",
        str(cert_path),
        f"https://localhost:{https_port}/healthz.txt",
    ]
    result = subprocess.run(args, text=True, capture_output=True, check=False)
    if expect_success:
        if result.returncode != 0 or result.stdout != "ok-vision\n":
            raise RuntimeError(f"curl through vision failed rc={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}")
        return
    if result.returncode == 0:
        raise RuntimeError(f"curl unexpectedly succeeded stdout={result.stdout!r}")


def start_stack(repo_root, binary, runtime_env, temp_root, *, server_vision, client_vision, response_text):
    temp_root.mkdir(parents=True, exist_ok=True)
    server_port = allocate_tcp_port()
    socks_port = allocate_tcp_port()
    https_port = allocate_tcp_port()
    key_output = run_checked([str(binary), "x25519"], env=runtime_env, capture_output=True)
    private_key, public_key = parse_key_output(key_output.stdout)
    key_path, cert_path = build_cert(temp_root, "localhost")

    server_log = temp_root / f"server-{server_port}.log"
    client_log = temp_root / f"client-{socks_port}.log"
    https_log = temp_root / f"https-{https_port}.log"

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

    server_config_path = temp_root / f"server-{server_port}.json"
    client_config_path = temp_root / f"client-{socks_port}.json"
    save_json(server_config_path, server_cfg)
    save_json(client_config_path, client_cfg)

    processes = []
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
            response_text,
        ],
        str(https_log),
    )
    processes.append(https_process)

    server_process = start_process([str(binary), "-c", str(server_config_path)], str(server_log), extra_env=runtime_env)
    processes.append(server_process)
    client_process = start_process([str(binary), "-c", str(client_config_path)], str(client_log), extra_env=runtime_env)
    processes.append(client_process)

    wait_for_log_text(server_log, f"listen 127.0.0.1:{server_port} reality inbound listening", 20, "vision server log", processes)
    wait_for_log_text(client_log, f"listen 127.0.0.1:{socks_port} socks listening", 20, "vision client log", processes)
    wait_for_port("127.0.0.1", socks_port, 20, "vision socks proxy", processes)
    return {
        "processes": processes,
        "server_log": server_log,
        "client_log": client_log,
        "https_log": https_log,
        "socks_port": socks_port,
        "https_port": https_port,
        "cert_path": cert_path,
    }


def stop_processes(processes):
    for process in reversed(processes):
        try:
            process.terminate()
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(description="TCP Vision REALITY integration test")
    parser.add_argument("--binary", default=str(pathlib.Path("build") / "socks"))
    parser.add_argument("--keep-artifacts", action="store_true")
    args = parser.parse_args()

    repo_root = pathlib.Path(__file__).resolve().parents[1]
    binary = pathlib.Path(args.binary)
    if not binary.is_absolute():
        binary = (repo_root / binary).resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError(f"binary not found: {binary}")
    for command_name in ("curl", "openssl"):
        if shutil.which(command_name) is None:
            raise RuntimeError(f"missing dependency: {command_name}")

    temp_root = pathlib.Path(tempfile.mkdtemp(prefix=".tmp-reality-vision.", dir=repo_root))
    active_processes = []
    try:
        runtime_env = build_runtime_env(binary)

        success_stack = start_stack(
            repo_root,
            binary,
            runtime_env,
            temp_root / "success",
            server_vision=True,
            client_vision=True,
            response_text="ok-vision",
        )
        active_processes = success_stack["processes"]
        run_curl_through_socks(
            success_stack["socks_port"],
            success_stack["cert_path"],
            success_stack["https_port"],
            expect_success=True,
        )
        wait_for_any_log_text(
            [success_stack["server_log"], success_stack["client_log"]],
            "enter_raw_write_mode",
            10,
            "vision direct write",
            success_stack["processes"],
        )
        stop_processes(success_stack["processes"])
        active_processes = []

        reject_stack_root = temp_root / "reject"
        reject_stack = start_stack(
            repo_root,
            binary,
            runtime_env,
            reject_stack_root,
            server_vision=False,
            client_vision=True,
            response_text="ok-vision",
        )
        active_processes = reject_stack["processes"]
        run_curl_through_socks(
            reject_stack["socks_port"],
            reject_stack["cert_path"],
            reject_stack["https_port"],
            expect_success=False,
        )
        wait_for_log_text(
            reject_stack["server_log"],
            "vision requested but inbound disabled",
            10,
            "vision rejection log",
            reject_stack["processes"],
        )

        print("reality_vision_tcp ok")
        print("reality_vision_reject ok")
        return 0
    except Exception as exc:
        print(f"test failed {exc}", file=sys.stderr)
        for path in temp_root.glob("**/*.log"):
            print(f"===== {path.relative_to(temp_root)} =====", file=sys.stderr)
            print(tail_file(path), file=sys.stderr)
        raise
    finally:
        stop_processes(active_processes)
        if args.keep_artifacts:
            print(f"artifacts kept at {temp_root}", file=sys.stderr)
        else:
            subprocess.run(["rm", "-rf", str(temp_root)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    raise SystemExit(main())
