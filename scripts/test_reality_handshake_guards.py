#!/usr/bin/env python3

import argparse
import pathlib
import shutil
import subprocess
import sys
import tempfile

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


def run_guard_case(repo_root, binary, runtime_env, temp_root, case_name, client_outbound_overrides, expected_server_log="", expected_client_log=""):
    case_dir = temp_root / case_name
    case_dir.mkdir(parents=True, exist_ok=True)

    server_port = allocate_tcp_port()
    socks_port = allocate_tcp_port()
    https_port = allocate_tcp_port()

    origin_host = "localhost"
    socks_host = "127.0.0.1"
    reality_sni = "www.example.com"

    key_output = run_checked([str(binary), "x25519"], env=runtime_env, capture_output=True)
    private_key, public_key = parse_key_output(key_output.stdout)

    key_path, cert_path = build_cert(case_dir, origin_host)
    server_log = case_dir / "server.log"
    client_log = case_dir / "client.log"
    https_log = case_dir / "https.log"
    processes = []

    try:
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
        processes.append(https_process)

        server_cfg = make_reality_server_config(
            log_file=server_log,
            port=server_port,
            sni=reality_sni,
            private_key=private_key,
            public_key=public_key,
        )
        client_cfg = make_reality_client_config(
            log_file=client_log,
            socks_host=socks_host,
            socks_port=socks_port,
            server_port=server_port,
            sni=reality_sni,
            public_key=public_key,
            reality_settings_overrides=client_outbound_overrides,
        )

        save_json(case_dir / "server.json", server_cfg)
        save_json(case_dir / "client.json", client_cfg)

        server_process = start_process(
            [str(binary), "-c", str(case_dir / "server.json")],
            str(server_log),
            extra_env=runtime_env,
        )
        processes.append(server_process)

        client_process = start_process(
            [str(binary), "-c", str(case_dir / "client.json")],
            str(client_log),
            extra_env=runtime_env,
        )
        processes.append(client_process)

        wait_for_log_text(server_log, f"listen 127.0.0.1:{server_port} reality inbound listening", 20, f"{case_name} server log")
        wait_for_log_text(client_log, f"listen {socks_host}:{socks_port} socks listening", 20, f"{case_name} client log")
        wait_for_port(socks_host, socks_port, 20, f"{case_name} socks proxy")

        https_url = f"https://{origin_host}:{https_port}/healthz.txt"
        result = subprocess.run(
            [
                "curl",
                "--silent",
                "--show-error",
                "--fail",
                "--connect-timeout",
                "5",
                "--max-time",
                "10",
                "--proxy",
                f"socks5://{socks_host}:{socks_port}",
                "--cacert",
                str(cert_path),
                https_url,
            ],
            text=True,
            capture_output=True,
        )
        if result.returncode == 0 and result.stdout == "ok-https\n":
            raise RuntimeError(f"{case_name} unexpectedly succeeded")

        if expected_server_log:
            wait_for_log_text(server_log, expected_server_log, 10, f"{case_name} server log")
        if expected_client_log:
            wait_for_log_text(client_log, expected_client_log, 10, f"{case_name} client log")
    finally:
        for process in reversed(processes):
            try:
                process.terminate()
            except Exception:
                pass


def main():
    parser = argparse.ArgumentParser(description="Reality handshake guardrail tests")
    parser.add_argument("--binary", default=str(pathlib.Path("build") / "socks"), help="path to the socks binary")
    parser.add_argument("--keep-artifacts", action="store_true")
    args = parser.parse_args()

    repo_root = pathlib.Path(__file__).resolve().parents[1]
    binary = pathlib.Path(args.binary)
    if not binary.is_absolute():
        binary = (repo_root / binary).resolve()
    if not binary.is_file() or not binary.exists():
        raise RuntimeError(f"binary not found: {binary}")

    for command_name in ("python3", "curl", "openssl"):
        if shutil.which(command_name) is None:
            raise RuntimeError(f"missing dependency: {command_name}")

    temp_root = pathlib.Path(tempfile.mkdtemp(prefix=".tmp-reality-handshake-guards.", dir=repo_root))
    try:
        runtime_env = build_runtime_env(binary)

        run_guard_case(
            repo_root,
            binary,
            runtime_env,
            temp_root,
            "max_handshake_records_limit",
            {"max_handshake_records": 1},
            expected_client_log="too many handshake records",
        )
        print("max_handshake_records_limit ok")

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
            subprocess.run(["rm", "-rf", str(temp_root)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    raise SystemExit(main())
