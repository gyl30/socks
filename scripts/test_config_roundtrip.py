#!/usr/bin/env python3

import argparse
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

from test_reality_integration import allocate_tcp_port, build_runtime_env, save_json, start_process, tail_file, wait_for_log_text


def run_default_roundtrip(binary, runtime_env, temp_root):
    result = subprocess.run([str(binary), "config"], env=runtime_env, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"dump default config failed rc={result.returncode} stderr={result.stderr}")

    cfg = json.loads(result.stdout)
    listen_host = cfg["inbounds"][0]["settings"]["host"]
    listen_port = allocate_tcp_port()
    log_path = temp_root / "roundtrip.log"
    run_log = temp_root / "roundtrip.stdout.log"
    cfg["log"]["file"] = str(log_path)
    cfg["inbounds"][0]["settings"]["port"] = listen_port

    config_path = temp_root / "roundtrip.json"
    save_json(config_path, cfg)

    process = start_process([str(binary), "-c", str(config_path)], str(run_log), extra_env=runtime_env)
    try:
        wait_for_log_text(log_path, f"listen {listen_host}:{listen_port} socks listening", 20, "roundtrip log")
    finally:
        process.terminate()


def run_invalid_config_case(binary, runtime_env, temp_root):
    invalid_path = temp_root / "invalid.json"
    invalid_path.write_text("{\n", encoding="utf-8")

    result = subprocess.run([str(binary), "-c", str(invalid_path)], env=runtime_env, text=True, capture_output=True, check=False)
    if result.returncode == 0:
        raise RuntimeError("invalid config unexpectedly succeeded")

    combined = (result.stdout or "") + (result.stderr or "")
    if "json_parse" not in combined:
        raise RuntimeError(f"invalid config missing parse error output: {combined!r}")


def main():
    parser = argparse.ArgumentParser(description="Config dump/parse smoke test")
    parser.add_argument("--binary", default=str(pathlib.Path("build") / "socks"), help="path to the socks binary")
    parser.add_argument("--keep-artifacts", action="store_true")
    args = parser.parse_args()

    repo_root = pathlib.Path(__file__).resolve().parents[1]
    binary = pathlib.Path(args.binary)
    if not binary.is_absolute():
        binary = (repo_root / binary).resolve()
    if not binary.is_file() or not binary.exists():
        raise RuntimeError(f"binary not found: {binary}")

    temp_root = pathlib.Path(tempfile.mkdtemp(prefix=".tmp-config-roundtrip.", dir=repo_root))
    try:
        runtime_env = build_runtime_env(binary)
        run_default_roundtrip(binary, runtime_env, temp_root)
        print("default_roundtrip ok")
        run_invalid_config_case(binary, runtime_env, temp_root)
        print("invalid_config ok")
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
            shutil.rmtree(temp_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
