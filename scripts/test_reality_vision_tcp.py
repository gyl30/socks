#!/usr/bin/env python3

import argparse
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import threading

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


def assert_log_text_absent(paths, needle, label):
    for path in paths:
        content = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
        if needle in content:
            tails = "\n".join(f"===== {item.name} =====\n{tail_file(item)}" for item in paths)
            raise RuntimeError(f"unexpected {label} log text {needle!r}\n{tails}")


def read_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError("socket closed before expected bytes")
        data.extend(chunk)
    return bytes(data)


def read_until_eof(sock):
    data = bytearray()
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            return bytes(data)
        data.extend(chunk)


def socks5_connect(socks_port, target_host, target_port):
    sock = socket.create_connection(("127.0.0.1", socks_port), timeout=5)
    sock.settimeout(10)
    sock.sendall(b"\x05\x01\x00")
    if read_exact(sock, 2) != b"\x05\x00":
        sock.close()
        raise RuntimeError("socks5 auth negotiation failed")

    addr = socket.inet_aton(target_host)
    request = b"\x05\x01\x00\x01" + addr + target_port.to_bytes(2, "big")
    sock.sendall(request)
    reply = read_exact(sock, 4)
    if reply[1] != 0:
        sock.close()
        raise RuntimeError(f"socks5 connect failed rep={reply[1]}")
    if reply[3] == 1:
        read_exact(sock, 4)
    elif reply[3] == 3:
        read_exact(sock, read_exact(sock, 1)[0])
    elif reply[3] == 4:
        read_exact(sock, 16)
    else:
        sock.close()
        raise RuntimeError(f"socks5 reply atyp invalid atyp={reply[3]}")
    read_exact(sock, 2)
    return sock


def run_curl_through_socks(socks_port, cert_path, https_port, expect_success, expected_stdout="ok-vision\n", tls_version="1.3"):
    if tls_version == "1.3":
        tls_args = ["--tlsv1.3", "--tls-max", "1.3"]
    elif tls_version == "1.2":
        tls_args = ["--tlsv1.2", "--tls-max", "1.2"]
    else:
        raise RuntimeError(f"unsupported tls version {tls_version}")

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
        "20",
        "--proxy",
        f"socks5://127.0.0.1:{socks_port}",
        "--cacert",
        str(cert_path),
        f"https://localhost:{https_port}/healthz.txt",
    ]
    result = subprocess.run(args, text=True, capture_output=True, check=False)
    if expect_success:
        if result.returncode != 0 or result.stdout != expected_stdout:
            raise RuntimeError(f"curl through vision failed rc={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}")
        return
    if result.returncode == 0:
        raise RuntimeError(f"curl unexpectedly succeeded stdout={result.stdout!r}")


def run_plain_http_through_socks(socks_port, http_port):
    args = [
        "curl",
        "--silent",
        "--show-error",
        "--fail",
        "--ipv4",
        "--connect-timeout",
        "5",
        "--max-time",
        "20",
        "--proxy",
        f"socks5://127.0.0.1:{socks_port}",
        f"http://127.0.0.1:{http_port}/plain.txt",
    ]
    result = subprocess.run(args, text=True, capture_output=True, check=False)
    if result.returncode != 0 or result.stdout != "ok-plain\n":
        raise RuntimeError(f"plain http through vision failed rc={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}")


def start_plain_http_server(repo_root, temp_root, processes):
    http_port = allocate_tcp_port()
    http_dir = temp_root / f"plain-http-{http_port}"
    http_dir.mkdir(parents=True, exist_ok=True)
    (http_dir / "plain.txt").write_text("ok-plain\n", encoding="utf-8")
    http_log = temp_root / f"plain-http-{http_port}.log"
    process = start_process(
        [
            sys.executable,
            str(repo_root / "scripts/test_http_server.py"),
            "--host",
            "127.0.0.1",
            "--port",
            str(http_port),
            "--directory",
            str(http_dir),
        ],
        str(http_log),
    )
    processes.append(process)
    wait_for_port("127.0.0.1", http_port, 20, "plain http origin", processes)
    return http_port


def start_half_close_server():
    ready = threading.Event()
    done = threading.Event()
    errors = []
    port_holder = []

    def serve():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                listener.settimeout(20)
                port_holder.append(listener.getsockname()[1])
                ready.set()
                conn, _addr = listener.accept()
                with conn:
                    conn.settimeout(20)
                    request = read_until_eof(conn)
                    if request != b"ping-half-close":
                        errors.append(f"half close request mismatch request={request!r}")
                    conn.sendall(b"half-close-ok")
                    conn.shutdown(socket.SHUT_WR)
        except Exception as exc:
            errors.append(str(exc))
        finally:
            done.set()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    if not ready.wait(10):
        raise RuntimeError("half close server did not start")
    return port_holder[0], done, errors


def run_half_close_through_socks(socks_port):
    target_port, done, errors = start_half_close_server()
    with socks5_connect(socks_port, "127.0.0.1", target_port) as sock:
        sock.sendall(b"ping-half-close")
        sock.shutdown(socket.SHUT_WR)
        response = read_until_eof(sock)
    if response != b"half-close-ok":
        raise RuntimeError(f"half close response mismatch response={response!r}")
    if not done.wait(10):
        raise RuntimeError("half close server did not finish")
    if errors:
        raise RuntimeError("; ".join(errors))


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
        "https_process": https_process,
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

        large_response = "ok-vision-" + ("x" * 32768)
        success_stack = start_stack(
            repo_root,
            binary,
            runtime_env,
            temp_root / "success",
            server_vision=True,
            client_vision=True,
            response_text=large_response,
        )
        active_processes = success_stack["processes"]
        run_curl_through_socks(
            success_stack["socks_port"],
            success_stack["cert_path"],
            success_stack["https_port"],
            expect_success=True,
            expected_stdout=f"{large_response}\n",
        )
        wait_for_log_text(success_stack["client_log"], "vision requested", 10, "vision request log", success_stack["processes"])
        wait_for_log_text(success_stack["client_log"], "vision accepted", 10, "vision client accept log", success_stack["processes"])
        wait_for_log_text(success_stack["server_log"], "vision accepted", 10, "vision server accept log", success_stack["processes"])
        for log_path, label in ((success_stack["server_log"], "server"), (success_stack["client_log"], "client")):
            wait_for_log_text(log_path, "enter_raw_write_mode", 10, f"vision direct {label} write", success_stack["processes"])
            wait_for_log_text(log_path, "enter_raw_read_mode", 10, f"vision direct {label} read", success_stack["processes"])
        stop_processes(success_stack["processes"])
        active_processes = []

        tls12_stack = start_stack(
            repo_root,
            binary,
            runtime_env,
            temp_root / "tls12",
            server_vision=True,
            client_vision=True,
            response_text="ok-tls12",
        )
        active_processes = tls12_stack["processes"]
        run_curl_through_socks(
            tls12_stack["socks_port"],
            tls12_stack["cert_path"],
            tls12_stack["https_port"],
            expect_success=True,
            expected_stdout="ok-tls12\n",
            tls_version="1.2",
        )
        assert_log_text_absent([tls12_stack["server_log"], tls12_stack["client_log"]], "enter_raw_write_mode", "tls12 fallback write")
        assert_log_text_absent([tls12_stack["server_log"], tls12_stack["client_log"]], "enter_raw_read_mode", "tls12 fallback read")
        stop_processes(tls12_stack["processes"])
        active_processes = []

        plain_stack = start_stack(
            repo_root,
            binary,
            runtime_env,
            temp_root / "plain",
            server_vision=True,
            client_vision=True,
            response_text="unused",
        )
        active_processes = plain_stack["processes"]
        plain_http_port = start_plain_http_server(repo_root, temp_root / "plain", plain_stack["processes"])
        run_plain_http_through_socks(plain_stack["socks_port"], plain_http_port)
        run_half_close_through_socks(plain_stack["socks_port"])
        assert_log_text_absent([plain_stack["server_log"], plain_stack["client_log"]], "enter_raw_write_mode", "plain fallback write")
        assert_log_text_absent([plain_stack["server_log"], plain_stack["client_log"]], "enter_raw_read_mode", "plain fallback read")
        stop_processes(plain_stack["processes"])
        active_processes = []

        connect_fail_stack = start_stack(
            repo_root,
            binary,
            runtime_env,
            temp_root / "connect-fail",
            server_vision=True,
            client_vision=True,
            response_text="unused",
        )
        active_processes = connect_fail_stack["processes"]
        connect_fail_stack["https_process"].terminate()
        connect_fail_stack["processes"].remove(connect_fail_stack["https_process"])
        run_curl_through_socks(
            connect_fail_stack["socks_port"],
            connect_fail_stack["cert_path"],
            connect_fail_stack["https_port"],
            expect_success=False,
        )
        assert_log_text_absent([connect_fail_stack["server_log"], connect_fail_stack["client_log"]], "vision accepted", "connect failure accept")
        stop_processes(connect_fail_stack["processes"])
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
        print("reality_vision_tls12_fallback ok")
        print("reality_vision_plain_tcp ok")
        print("reality_vision_connect_fail ok")
        print("reality_vision_half_close ok")
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
