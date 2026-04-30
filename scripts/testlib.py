#!/usr/bin/env python3

import json
import os
import pathlib
import re
import socket
import subprocess
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
        command_text = " ".join(str(arg) for arg in args)
        raise RuntimeError(f"command failed: {command_text}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    return result


def _check_processes_running(processes, label):
    if processes is None:
        return
    for process in processes:
        if process.process.poll() is not None:
            raise RuntimeError(f"process exited early while waiting for {label}")


def wait_for_port(host, port, deadline_seconds, label, processes=None):
    deadline = time.time() + deadline_seconds
    last_error = None
    while time.time() < deadline:
        _check_processes_running(processes, label)
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


def wait_for_log_text(path, needle, deadline_seconds, label, processes=None):
    deadline = time.time() + deadline_seconds
    while time.time() < deadline:
        _check_processes_running(processes, label)
        if path.exists():
            text = path.read_text(encoding="utf-8", errors="replace")
            if needle in text:
                return text
        time.sleep(0.2)
    raise RuntimeError(f"timeout waiting for {label} log text {needle!r}")


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


def allocate_udp_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def save_json(path, value):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2)
        handle.write("\n")


def parse_key_output(output):
    private_match = re.search(r"private key:\s+(\S+)", output)
    public_match = re.search(r"public key:\s+(\S+)", output)
    if private_match is None or public_match is None:
        raise RuntimeError("failed to parse x25519 key output")
    return private_match.group(1), public_match.group(1)


def make_reality_server_config(
    *,
    log_file,
    port,
    sni,
    private_key,
    public_key,
    short_id="0102030405060708",
    workers=1,
    idle_timeout=30,
    web_port=None,
    outbounds=None,
    routing=None,
):
    cfg = {
        "workers": workers,
        "log": {
            "level": "debug",
            "file": str(log_file),
        },
        "inbounds": [
            {
                "type": "reality",
                "tag": "reality-in",
                "settings": {
                    "host": "127.0.0.1",
                    "port": port,
                    "sni": sni,
                    "private_key": private_key,
                    "public_key": public_key,
                    "short_id": short_id,
                    "replay_cache_max_entries": 100000,
                },
            }
        ],
        "outbounds": outbounds
        if outbounds is not None
        else [
            {
                "type": "direct",
                "tag": "direct",
            }
        ],
        "routing": routing
        if routing is not None
        else [
            {
                "type": "inbound",
                "values": ["reality-in"],
                "out": "direct",
            }
        ],
        "timeout": {
            "read": 5,
            "write": 5,
            "connect": 5,
            "idle": idle_timeout,
        },
    }
    if web_port is not None:
        cfg["web"] = {
            "enabled": True,
            "host": "127.0.0.1",
            "port": web_port,
        }
    return cfg


def make_reality_client_config(
    *,
    log_file,
    socks_port,
    server_port,
    sni,
    public_key,
    short_id="0102030405060708",
    socks_host="127.0.0.1",
    workers=1,
    idle_timeout=30,
    web_port=None,
    reality_settings_overrides=None,
    extra_outbounds=None,
    routing=None,
):
    reality_settings = {
        "host": "127.0.0.1",
        "port": server_port,
        "sni": sni,
        "fingerprint": "random",
        "public_key": public_key,
        "short_id": short_id,
        "max_handshake_records": 256,
    }
    if reality_settings_overrides is not None:
        reality_settings.update(reality_settings_overrides)

    outbounds = [
        {
            "type": "reality",
            "tag": "reality-out",
            "settings": reality_settings,
        },
        {
            "type": "direct",
            "tag": "direct",
        },
    ]
    if extra_outbounds is not None:
        outbounds.extend(extra_outbounds)

    cfg = {
        "workers": workers,
        "log": {
            "level": "debug",
            "file": str(log_file),
        },
        "inbounds": [
            {
                "type": "socks",
                "tag": "socks-in",
                "settings": {
                    "host": socks_host,
                    "port": socks_port,
                    "auth": False,
                },
            }
        ],
        "outbounds": outbounds,
        "routing": routing
        if routing is not None
        else [
            {
                "type": "inbound",
                "values": ["socks-in"],
                "out": "reality-out",
            }
        ],
        "timeout": {
            "read": 5,
            "write": 5,
            "connect": 5,
            "idle": idle_timeout,
        },
    }
    if web_port is not None:
        cfg["web"] = {
            "enabled": True,
            "host": "127.0.0.1",
            "port": web_port,
        }
    return cfg


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
        ]
    )
    return key_path, cert_path


def start_process(args, stdout_path, extra_env=None):
    return ManagedProcess(args, stdout_path, extra_env=extra_env)


def _append_runtime_dir(runtime_dirs, path):
    if not path or not os.path.isdir(path) or path in runtime_dirs:
        return
    runtime_dirs.append(path)


def _append_runtime_dirs(runtime_dirs, raw):
    if not raw:
        return
    for path in raw.split(":"):
        _append_runtime_dir(runtime_dirs, path)


def _append_root_runtime_dirs(runtime_dirs, root):
    if not root:
        return
    _append_runtime_dir(runtime_dirs, os.path.join(root, "lib64"))
    _append_runtime_dir(runtime_dirs, os.path.join(root, "lib"))


def _read_binary_runpath(binary):
    try:
        result = subprocess.run(
            ["readelf", "-d", str(binary)],
            text=True,
            capture_output=True,
            check=False,
        )
    except FileNotFoundError:
        return ""
    if result.returncode != 0:
        return ""
    match = re.search(r"\((?:RUNPATH|RPATH)\).*?\[(.*?)\]", result.stdout)
    if match is None:
        return ""
    return match.group(1)


def build_runtime_env(binary):
    runtime_dirs = []
    _append_runtime_dirs(runtime_dirs, os.environ.get("SOCKS_RUNTIME_LIB_DIRS", ""))
    _append_root_runtime_dirs(runtime_dirs, os.environ.get("OPENSSL_ROOT_DIR", ""))
    _append_root_runtime_dirs(runtime_dirs, os.environ.get("BROTLI_ROOT_DIR", ""))
    _append_runtime_dirs(runtime_dirs, _read_binary_runpath(pathlib.Path(binary)))
    _append_runtime_dirs(runtime_dirs, os.environ.get("LD_LIBRARY_PATH", ""))
    if not runtime_dirs:
        return {}
    return {"LD_LIBRARY_PATH": ":".join(runtime_dirs)}
