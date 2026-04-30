#!/usr/bin/env python3

import argparse
import copy
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

from testlib import allocate_tcp_port, build_runtime_env, parse_key_output, save_json, start_process, tail_file, wait_for_log_text


def assert_no_usage(case_name, output):
    if "Usage:" in output:
        raise RuntimeError(f"{case_name} unexpectedly printed usage: {output!r}")


def dump_default_config(binary, runtime_env):
    result = subprocess.run([str(binary), "config"], env=runtime_env, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"dump default config failed rc={result.returncode} stderr={result.stderr}")
    return json.loads(result.stdout)


def run_default_roundtrip(binary, runtime_env, temp_root):
    cfg = dump_default_config(binary, runtime_env)
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


def run_marked_roundtrip(binary, runtime_env, temp_root):
    cfg = dump_default_config(binary, runtime_env)
    listen_host = cfg["inbounds"][0]["settings"]["host"]
    listen_port = allocate_tcp_port()
    log_path = temp_root / "marked-roundtrip.log"
    run_log = temp_root / "marked-roundtrip.stdout.log"
    cfg["log"]["file"] = str(log_path)
    cfg["inbounds"][0]["settings"]["port"] = listen_port
    cfg["inbounds"][0]["mark"] = 17
    cfg["outbounds"][0]["mark"] = 23

    config_path = temp_root / "marked-roundtrip.json"
    save_json(config_path, cfg)

    process = start_process([str(binary), "-c", str(config_path)], str(run_log), extra_env=runtime_env)
    try:
        wait_for_log_text(log_path, f"listen {listen_host}:{listen_port} socks listening", 20, "marked roundtrip log")
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
    assert_no_usage("invalid_config", combined)


def run_invalid_reality_config_case(binary, runtime_env, temp_root, case_name, config_value, expected_error):
    config_path = temp_root / f"{case_name}.json"
    save_json(config_path, config_value)

    result = subprocess.run([str(binary), "-c", str(config_path)], env=runtime_env, text=True, capture_output=True, check=False)
    if result.returncode == 0:
        raise RuntimeError(f"{case_name} unexpectedly succeeded")

    combined = (result.stdout or "") + (result.stderr or "")
    if expected_error not in combined:
        raise RuntimeError(f"{case_name} missing error {expected_error!r} output={combined!r}")
    assert_no_usage(case_name, combined)


def run_invalid_config_value_case(binary, runtime_env, temp_root, case_name, config_value, expected_error):
    config_path = temp_root / f"{case_name}.json"
    save_json(config_path, config_value)

    result = subprocess.run([str(binary), "-c", str(config_path)], env=runtime_env, text=True, capture_output=True, check=False)
    if result.returncode == 0:
        raise RuntimeError(f"{case_name} unexpectedly succeeded")

    combined = (result.stdout or "") + (result.stderr or "")
    if expected_error not in combined:
        raise RuntimeError(f"{case_name} missing error {expected_error!r} output={combined!r}")
    assert_no_usage(case_name, combined)


def run_invalid_reality_config_cases(binary, runtime_env, temp_root):
    base_cfg = dump_default_config(binary, runtime_env)
    key_output = subprocess.run([str(binary), "x25519"], env=runtime_env, text=True, capture_output=True, check=False)
    if key_output.returncode != 0:
        raise RuntimeError(f"dump x25519 failed rc={key_output.returncode} stderr={key_output.stderr}")
    private_key, _ = parse_key_output(key_output.stdout)

    cases = []

    invalid_outbound_public_key = copy.deepcopy(base_cfg)
    invalid_outbound_public_key["outbounds"][0]["settings"]["public_key"] = "xyz"
    cases.append(
        (
            "invalid_outbound_public_key",
            invalid_outbound_public_key,
            "outbounds[0].settings.public_key hex length invalid",
        )
    )

    invalid_outbound_short_id = copy.deepcopy(base_cfg)
    invalid_outbound_short_id["outbounds"][0]["settings"]["short_id"] = "001"
    cases.append(
        (
            "invalid_outbound_short_id",
            invalid_outbound_short_id,
            "outbounds[0].settings.short_id hex length invalid",
        )
    )

    invalid_outbound_fingerprint = copy.deepcopy(base_cfg)
    invalid_outbound_fingerprint["outbounds"][0]["settings"]["fingerprint"] = "not-real"
    cases.append(
        (
            "invalid_outbound_fingerprint",
            invalid_outbound_fingerprint,
            "outbounds[0].settings.fingerprint invalid",
        )
    )

    invalid_outbound_port_zero = copy.deepcopy(base_cfg)
    invalid_outbound_port_zero["outbounds"][0]["settings"]["port"] = 0
    cases.append(
        (
            "invalid_outbound_port_zero",
            invalid_outbound_port_zero,
            "outbounds[0].settings.port out_of_range",
        )
    )

    invalid_inbound_private_key = copy.deepcopy(base_cfg)
    invalid_inbound_private_key["inbounds"] = [
        {
            "type": "reality",
            "tag": "reality-in",
            "settings": {
                "host": "127.0.0.1",
                "port": allocate_tcp_port(),
                "sni": "localhost",
                "site_port": 443,
                "private_key": "xyz",
                "short_id": "0102030405060708",
                "replay_cache_max_entries": 1000,
            },
        }
    ]
    invalid_inbound_private_key["outbounds"] = [{"type": "direct", "tag": "direct"}]
    invalid_inbound_private_key["routing"] = [{"type": "inbound", "values": ["reality-in"], "out": "direct"}]
    cases.append(
        (
            "invalid_inbound_private_key",
            invalid_inbound_private_key,
            "inbounds[0].settings.private_key hex length invalid",
        )
    )

    invalid_inbound_short_id = copy.deepcopy(base_cfg)
    invalid_inbound_short_id["inbounds"] = [
        {
            "type": "reality",
            "tag": "reality-in",
            "settings": {
                "host": "127.0.0.1",
                "port": allocate_tcp_port(),
                "sni": "localhost",
                "site_port": 443,
                "private_key": private_key,
                "short_id": "xyz",
                "replay_cache_max_entries": 1000,
            },
        }
    ]
    invalid_inbound_short_id["outbounds"] = [{"type": "direct", "tag": "direct"}]
    invalid_inbound_short_id["routing"] = [{"type": "inbound", "values": ["reality-in"], "out": "direct"}]
    cases.append(
        (
            "invalid_inbound_short_id",
            invalid_inbound_short_id,
            "inbounds[0].settings.short_id hex length invalid",
        )
    )

    valid_inbound_reality = copy.deepcopy(invalid_inbound_short_id)
    valid_inbound_reality["inbounds"][0]["settings"]["short_id"] = "0102030405060708"

    invalid_inbound_port_zero = copy.deepcopy(valid_inbound_reality)
    invalid_inbound_port_zero["inbounds"][0]["settings"]["port"] = 0
    cases.append(
        (
            "invalid_inbound_port_zero",
            invalid_inbound_port_zero,
            "inbounds[0].settings.port out_of_range",
        )
    )

    invalid_inbound_site_port_zero = copy.deepcopy(valid_inbound_reality)
    invalid_inbound_site_port_zero["inbounds"][0]["settings"]["site_port"] = 0
    cases.append(
        (
            "invalid_inbound_site_port_zero",
            invalid_inbound_site_port_zero,
            "inbounds[0].settings.site_port out_of_range",
        )
    )

    invalid_inbound_replay_cache_zero = copy.deepcopy(valid_inbound_reality)
    invalid_inbound_replay_cache_zero["inbounds"][0]["settings"]["replay_cache_max_entries"] = 0
    cases.append(
        (
            "invalid_inbound_replay_cache_zero",
            invalid_inbound_replay_cache_zero,
            "inbounds[0].settings.replay_cache_max_entries out_of_range",
        )
    )

    for case_name, config_value, expected_error in cases:
        run_invalid_reality_config_case(binary, runtime_env, temp_root, case_name, config_value, expected_error)
        print(f"{case_name} ok")


def run_invalid_route_config_case(binary, runtime_env, temp_root):
    cfg = dump_default_config(binary, runtime_env)
    cfg["routing"][0]["out"] = "missing-outbound"

    config_path = temp_root / "invalid_route.json"
    save_json(config_path, cfg)

    result = subprocess.run([str(binary), "-c", str(config_path)], env=runtime_env, text=True, capture_output=True, check=False)
    if result.returncode == 0:
        raise RuntimeError("invalid_route unexpectedly succeeded")

    combined = (result.stdout or "") + (result.stderr or "")
    if "routing[0] outbound_not_found" not in combined:
        raise RuntimeError(f"invalid_route missing outbound_not_found output={combined!r}")
    assert_no_usage("invalid_route", combined)


def run_invalid_route_inbound_ref_case(binary, runtime_env, temp_root):
    cfg = dump_default_config(binary, runtime_env)
    cfg["routing"][0]["values"] = ["missing-inbound"]

    run_invalid_config_value_case(
        binary,
        runtime_env,
        temp_root,
        "invalid_route_inbound_ref",
        cfg,
        "routing[0] inbound_not_found",
    )


def run_invalid_general_config_cases(binary, runtime_env, temp_root):
    base_cfg = dump_default_config(binary, runtime_env)

    invalid_port = copy.deepcopy(base_cfg)
    invalid_port["inbounds"][0]["settings"]["port"] = 70000
    run_invalid_config_value_case(
        binary,
        runtime_env,
        temp_root,
        "invalid_socks_port_overflow",
        invalid_port,
        "inbounds[0].settings.port out_of_range",
    )

    invalid_zero_port = copy.deepcopy(base_cfg)
    invalid_zero_port["inbounds"][0]["settings"]["port"] = 0
    run_invalid_config_value_case(
        binary,
        runtime_env,
        temp_root,
        "invalid_socks_port_zero",
        invalid_zero_port,
        "inbounds[0].settings.port out_of_range",
    )

    invalid_auth_username = copy.deepcopy(base_cfg)
    invalid_auth_username["inbounds"][0]["settings"]["auth"] = True
    run_invalid_config_value_case(
        binary,
        runtime_env,
        temp_root,
        "invalid_socks_auth_missing_username",
        invalid_auth_username,
        "inbounds[0].settings.username required_when_auth_enabled",
    )

    invalid_auth_password = copy.deepcopy(base_cfg)
    invalid_auth_password["inbounds"][0]["settings"]["auth"] = True
    invalid_auth_password["inbounds"][0]["settings"]["username"] = "user"
    run_invalid_config_value_case(
        binary,
        runtime_env,
        temp_root,
        "invalid_socks_auth_missing_password",
        invalid_auth_password,
        "inbounds[0].settings.password required_when_auth_enabled",
    )

    invalid_tun_prefix = copy.deepcopy(base_cfg)
    invalid_tun_prefix["inbounds"] = [
        {
            "type": "tun",
            "tag": "tun-in",
            "settings": {
                "name": "socks-test",
                "mtu": 1500,
                "ipv4": "198.18.0.1",
                "ipv4_prefix": 33,
                "ipv6": "fd00::1",
                "ipv6_prefix": 128,
            },
        }
    ]
    invalid_tun_prefix["routing"] = [{"type": "inbound", "values": ["tun-in"], "out": "direct"}]
    run_invalid_config_value_case(
        binary,
        runtime_env,
        temp_root,
        "invalid_tun_ipv4_prefix",
        invalid_tun_prefix,
        "inbounds[0].settings.ipv4_prefix out_of_range",
    )

    invalid_web_port = copy.deepcopy(base_cfg)
    invalid_web_port["web"] = {
        "enabled": True,
        "host": "127.0.0.1",
        "port": 0,
    }
    run_invalid_config_value_case(
        binary,
        runtime_env,
        temp_root,
        "invalid_web_port_zero",
        invalid_web_port,
        "web.port out_of_range",
    )

    invalid_duplicate_inbound_tag = copy.deepcopy(base_cfg)
    invalid_duplicate_inbound_tag["inbounds"].append(copy.deepcopy(invalid_duplicate_inbound_tag["inbounds"][0]))
    run_invalid_config_value_case(
        binary,
        runtime_env,
        temp_root,
        "invalid_duplicate_inbound_tag",
        invalid_duplicate_inbound_tag,
        "inbounds[1] duplicate_tag",
    )

    invalid_duplicate_outbound_tag = copy.deepcopy(base_cfg)
    invalid_duplicate_outbound_tag["outbounds"].append(copy.deepcopy(invalid_duplicate_outbound_tag["outbounds"][0]))
    run_invalid_config_value_case(
        binary,
        runtime_env,
        temp_root,
        "invalid_duplicate_outbound_tag",
        invalid_duplicate_outbound_tag,
        "outbounds[3] duplicate_tag",
    )

    invalid_reality_outbound_missing_settings = copy.deepcopy(base_cfg)
    invalid_reality_outbound_missing_settings["outbounds"][0].pop("settings")
    run_invalid_config_value_case(
        binary,
        runtime_env,
        temp_root,
        "invalid_reality_outbound_missing_settings",
        invalid_reality_outbound_missing_settings,
        "outbounds[0].settings missing",
    )

    invalid_reality_outbound_missing_public_key = copy.deepcopy(base_cfg)
    invalid_reality_outbound_missing_public_key["outbounds"][0]["settings"].pop("public_key")
    run_invalid_config_value_case(
        binary,
        runtime_env,
        temp_root,
        "invalid_reality_outbound_missing_public_key",
        invalid_reality_outbound_missing_public_key,
        "outbounds[0].settings.public_key missing",
    )

    invalid_reality_outbound_handshake_limit = copy.deepcopy(base_cfg)
    invalid_reality_outbound_handshake_limit["outbounds"][0]["settings"]["max_handshake_records"] = 0
    run_invalid_config_value_case(
        binary,
        runtime_env,
        temp_root,
        "invalid_reality_outbound_zero_max_handshake_records",
        invalid_reality_outbound_handshake_limit,
        "outbounds[0].settings.max_handshake_records out_of_range",
    )

    invalid_socks_outbound_auth_username = copy.deepcopy(base_cfg)
    invalid_socks_outbound_auth_username["outbounds"] = [
        {
            "type": "socks",
            "tag": "socks-out",
            "settings": {
                "host": "127.0.0.1",
                "port": allocate_tcp_port(),
                "auth": True,
            },
        },
        {
            "type": "block",
            "tag": "block",
        },
    ]
    invalid_socks_outbound_auth_username["routing"] = [{"type": "inbound", "values": ["socks-in"], "out": "socks-out"}]
    run_invalid_config_value_case(
        binary,
        runtime_env,
        temp_root,
        "invalid_socks_outbound_auth_missing_username",
        invalid_socks_outbound_auth_username,
        "outbounds[0].settings.username required_when_auth_enabled",
    )

    invalid_socks_outbound_auth_password = copy.deepcopy(invalid_socks_outbound_auth_username)
    invalid_socks_outbound_auth_password["outbounds"][0]["settings"]["username"] = "user"
    run_invalid_config_value_case(
        binary,
        runtime_env,
        temp_root,
        "invalid_socks_outbound_auth_missing_password",
        invalid_socks_outbound_auth_password,
        "outbounds[0].settings.password required_when_auth_enabled",
    )


def main():
    parser = argparse.ArgumentParser(description="Config roundtrip and validation test")
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
        run_marked_roundtrip(binary, runtime_env, temp_root)
        print("marked_roundtrip ok")
        run_invalid_config_case(binary, runtime_env, temp_root)
        print("invalid_config ok")
        run_invalid_reality_config_cases(binary, runtime_env, temp_root)
        run_invalid_general_config_cases(binary, runtime_env, temp_root)
        print("invalid_general_config ok")
        run_invalid_route_config_case(binary, runtime_env, temp_root)
        print("invalid_route ok")
        run_invalid_route_inbound_ref_case(binary, runtime_env, temp_root)
        print("invalid_route_inbound_ref ok")
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
