#!/usr/bin/env python3

import argparse
import json
import pathlib
import shutil
import sys
import tempfile
import time
import urllib.request

from testlib import (
    allocate_tcp_port,
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


def fetch_json(url):
    with urllib.request.urlopen(url, timeout=3) as response:
        return json.load(response)


def assert_no_request_done(web_port, deadline_seconds):
    deadline = time.time() + deadline_seconds
    last_payload = None
    while time.time() < deadline:
        payload = fetch_json(f"http://127.0.0.1:{web_port}/api/traces/events?stage=request_done&inbound_tag=reality-in&limit=20")
        last_payload = payload
        if payload.get("count") == 0 and not payload.get("events"):
            return
        time.sleep(0.2)
    raise RuntimeError(f"unexpected request_done events: {last_payload}")


def run_invalid_initial_request_case(helper, client_config_path, helper_env, payload_hex):
    run_checked([str(helper), str(client_config_path), "reality-out", payload_hex], env=helper_env, capture_output=True)


def main():
    parser = argparse.ArgumentParser(description="Reality invalid initial request guardrail tests")
    parser.add_argument("--binary", default=str(pathlib.Path("build") / "socks"), help="path to the socks binary")
    parser.add_argument(
        "--helper",
        default=str(pathlib.Path("build") / "test_reality_invalid_initial_request_client"),
        help="path to the invalid reality initial request helper",
    )
    parser.add_argument("--keep-artifacts", action="store_true")
    args = parser.parse_args()

    repo_root = pathlib.Path(__file__).resolve().parents[1]
    binary = pathlib.Path(args.binary)
    if not binary.is_absolute():
        binary = (repo_root / binary).resolve()
    if not binary.is_file():
        raise RuntimeError(f"binary not found: {binary}")

    helper = pathlib.Path(args.helper)
    if not helper.is_absolute():
        helper = (repo_root / helper).resolve()
    if not helper.is_file():
        raise RuntimeError(f"helper not found: {helper}")

    if shutil.which("python3") is None:
        raise RuntimeError("missing dependency: python3")

    temp_root = pathlib.Path(tempfile.mkdtemp(prefix=".tmp-reality-protocol-guards.", dir=repo_root))
    server_process = None
    try:
        runtime_env = build_runtime_env(binary)
        helper_env = build_runtime_env(helper)
        helper_env.update(runtime_env)

        server_port = allocate_tcp_port()
        web_port = allocate_tcp_port()
        dummy_socks_port = allocate_tcp_port()
        server_log = temp_root / "server.log"
        helper_log = temp_root / "helper.log"

        key_output = run_checked([str(binary), "x25519"], env=runtime_env, capture_output=True)
        private_key, public_key = parse_key_output(key_output.stdout)

        server_cfg = make_reality_server_config(
            log_file=server_log,
            port=server_port,
            sni="www.example.com",
            private_key=private_key,
            public_key=public_key,
            web_port=web_port,
        )
        client_cfg = make_reality_client_config(
            log_file=helper_log,
            socks_port=dummy_socks_port,
            server_port=server_port,
            sni="www.example.com",
            public_key=public_key,
        )

        server_config_path = temp_root / "server.json"
        client_config_path = temp_root / "client.json"
        save_json(server_config_path, server_cfg)
        save_json(client_config_path, client_cfg)

        server_process = start_process([str(binary), "-c", str(server_config_path)], str(server_log), extra_env=runtime_env)
        wait_for_log_text(server_log, f"listen 127.0.0.1:{server_port} reality inbound listening", 20, "reality protocol server log", [server_process])
        wait_for_port("127.0.0.1", server_port, 20, "reality protocol inbound", [server_process])
        wait_for_port("127.0.0.1", web_port, 20, "reality protocol trace web", [server_process])

        run_invalid_initial_request_case(helper, client_config_path, helper_env, "0800")
        wait_for_log_text(server_log, "invalid initial proxy request payload_size 2", 10, "unknown initial request log", [server_process])
        print("unknown_initial_request ok")

        run_invalid_initial_request_case(helper, client_config_path, helper_env, "01")
        wait_for_log_text(server_log, "invalid initial proxy request payload_size 1", 10, "truncated initial request log", [server_process])
        print("truncated_initial_request ok")

        assert_no_request_done(web_port, 2)
        print("reality_protocol_guardrails ok")
    except Exception as exc:
        server_tail = tail_file(server_log) if 'server_log' in locals() else ""
        raise RuntimeError(f"{exc}\nserver log tail:\n{server_tail}") from exc
    finally:
        if server_process is not None:
            server_process.terminate()
        if args.keep_artifacts:
            print(f"kept artifacts at {temp_root}")
        else:
            shutil.rmtree(temp_root, ignore_errors=True)


if __name__ == "__main__":
    main()
