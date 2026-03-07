#!/usr/bin/env python3

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time


SHORT_ID = "0102030405060708"
HRR_RANDOM = bytes(
    [
        0xCF,
        0x21,
        0xAD,
        0x74,
        0xE5,
        0x9A,
        0x61,
        0x11,
        0xBE,
        0x1D,
        0x8C,
        0x02,
        0x1E,
        0x65,
        0xB8,
        0x91,
        0xC2,
        0xA2,
        0x11,
        0x16,
        0x7A,
        0xBB,
        0x8C,
        0x5E,
        0x07,
        0x9E,
        0x09,
        0xE2,
        0xC8,
        0xA8,
        0x33,
        0x9C,
    ]
)


def resolve_binary_path() -> str:
    if "BIN" in os.environ and os.environ["BIN"]:
        return os.path.abspath(os.environ["BIN"])

    candidates = [
        os.path.abspath("./build-review/socks"),
        os.path.abspath("./build/socks"),
    ]
    for candidate in candidates:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    raise FileNotFoundError("未找到 socks 可执行文件，请设置 BIN 或先编译")


def generate_keys(bin_path: str) -> tuple[str, str]:
    output = subprocess.check_output([bin_path, "x25519"], text=True)
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    private_key = lines[0].split(": ", 1)[1].strip()
    public_key = lines[1].split(": ", 1)[1].strip()
    return private_key, public_key


def pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def recv_exact(conn: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise ConnectionError("连接提前关闭")
        data.extend(chunk)
    return bytes(data)


def parse_client_hello(record_body: bytes) -> tuple[bytes, int]:
    if len(record_body) < 4 or record_body[0] != 0x01:
        raise ValueError("不是 client hello")

    msg_len = int.from_bytes(record_body[1:4], "big")
    if msg_len + 4 > len(record_body):
        raise ValueError("client hello 长度非法")

    body = record_body[4 : 4 + msg_len]
    pos = 0
    if len(body) < 2 + 32 + 1:
        raise ValueError("client hello 过短")
    pos += 2
    pos += 32

    session_id_len = body[pos]
    pos += 1
    if pos + session_id_len > len(body):
        raise ValueError("session id 越界")
    session_id = body[pos : pos + session_id_len]
    pos += session_id_len

    if pos + 2 > len(body):
        raise ValueError("cipher suites 长度缺失")
    cipher_suites_len = int.from_bytes(body[pos : pos + 2], "big")
    pos += 2
    if cipher_suites_len < 2 or pos + cipher_suites_len > len(body):
        raise ValueError("cipher suites 非法")

    cipher_suite = int.from_bytes(body[pos : pos + 2], "big")
    return session_id, cipher_suite


def build_hrr_record(session_id: bytes, cipher_suite: int) -> bytes:
    supported_versions_ext = b"\x00\x2b\x00\x02\x03\x04"
    key_share_ext = b"\x00\x33\x00\x02\x00\x1d"
    extensions = supported_versions_ext + key_share_ext

    body = bytearray()
    body.extend(b"\x03\x03")
    body.extend(HRR_RANDOM)
    body.append(len(session_id))
    body.extend(session_id)
    body.extend(cipher_suite.to_bytes(2, "big"))
    body.append(0x00)
    body.extend(len(extensions).to_bytes(2, "big"))
    body.extend(extensions)

    handshake = bytearray()
    handshake.append(0x02)
    handshake.extend(len(body).to_bytes(3, "big"))
    handshake.extend(body)

    record = bytearray()
    record.extend(b"\x16\x03\x03")
    record.extend(len(handshake).to_bytes(2, "big"))
    record.extend(handshake)
    return bytes(record)


class fake_hrr_server:
    def __init__(self, port: int):
        self.port = port
        self.ready = threading.Event()
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.connections_served = 0
        self.error = None

    def start(self) -> None:
        self.thread.start()
        if not self.ready.wait(timeout=2):
            raise TimeoutError("假 HRR 服务端启动超时")
        if self.error is not None:
            raise RuntimeError(f"假 HRR 服务端启动失败: {self.error}")

    def stop(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=2)

    def run(self) -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
                server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_sock.bind(("127.0.0.1", self.port))
                server_sock.listen(4)
                server_sock.settimeout(0.2)
                self.ready.set()

                while not self.stop_event.is_set():
                    try:
                        conn, _ = server_sock.accept()
                    except socket.timeout:
                        continue

                    with conn:
                        conn.settimeout(2)
                        header = recv_exact(conn, 5)
                        if header[0] != 0x16:
                            raise ValueError("客户端首个记录不是握手记录")
                        body_len = int.from_bytes(header[3:5], "big")
                        record_body = recv_exact(conn, body_len)
                        session_id, cipher_suite = parse_client_hello(record_body)
                        conn.sendall(build_hrr_record(session_id, cipher_suite))
                        self.connections_served += 1
                        time.sleep(0.1)
        except Exception as exc:
            self.error = exc
            self.ready.set()


def write_json(path: str, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


def write_file(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)


def read_text(path: str) -> str:
    if not os.path.exists(path):
        return ""
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def wait_for_log(log_path: str, needle: str, timeout_sec: float) -> bool:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        if needle in read_text(log_path):
            return True
        time.sleep(0.1)
    return False


def stop_process(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=3)
        return
    except subprocess.TimeoutExpired:
        pass

    proc.kill()
    proc.wait(timeout=3)


def build_client_config(remote_port: int, socks_port: int, public_key: str, private_key: str) -> dict:
    return {
        "mode": "client",
        "workers": 1,
        "log": {
            "level": "debug",
            "file": "client_hrr.log",
        },
        "inbound": {
            "host": "127.0.0.1",
            "port": socks_port,
        },
        "outbound": {
            "host": "127.0.0.1",
            "port": remote_port,
        },
        "socks": {
            "enabled": True,
            "host": "127.0.0.1",
            "port": socks_port,
            "auth": False,
        },
        "reality": {
            "sni": "example.com",
            "fingerprint": "chrome",
            "public_key": public_key,
            "private_key": private_key,
            "short_id": SHORT_ID,
        },
        "timeout": {
            "read": 5,
            "write": 5,
            "connect": 5,
            "idle": 30,
        },
        "limits": {
            "max_connections": 1,
            "max_handshake_records": 8,
        },
        "monitor": {
            "enabled": False,
        },
    }


def print_tail(log_path: str, line_count: int) -> None:
    text = read_text(log_path)
    lines = text.splitlines()
    for line in lines[-line_count:]:
        print(line)


def main() -> int:
    try:
        bin_path = resolve_binary_path()
    except Exception as exc:
        print(f"[FAIL] {exc}")
        return 1

    print(f"[INFO] 使用二进制 {bin_path}")
    private_key, public_key = generate_keys(bin_path)
    remote_port = pick_free_port()
    socks_port = pick_free_port()

    with tempfile.TemporaryDirectory(prefix="hrr-reject-") as tmp_dir:
        config_path = os.path.join(tmp_dir, "client_hrr.json")
        log_path = os.path.join(tmp_dir, "client_hrr.log")
        process_output_path = os.path.join(tmp_dir, "client_hrr.out")

        write_json(config_path, build_client_config(remote_port, socks_port, public_key, private_key))
        for rule_file in ("block_ip.txt", "direct_ip.txt", "proxy_domain.txt", "block_domain.txt", "direct_domain.txt"):
            write_file(os.path.join(tmp_dir, rule_file), "")

        server = fake_hrr_server(remote_port)
        server.start()

        env = os.environ.copy()
        env["SOCKS_CONFIG_DIR"] = tmp_dir

        with open(process_output_path, "wb") as process_output:
            proc = subprocess.Popen(
                [bin_path, "-c", config_path],
                cwd=tmp_dir,
                stdout=process_output,
                stderr=process_output,
                env=env,
            )

            matched = False
            try:
                matched = wait_for_log(log_path, "hello retry request not supported", 10.0)
            finally:
                stop_process(proc)
                server.stop()

        log_text = read_text(log_path)
        proc_returncode = proc.returncode
        process_output_text = read_text(process_output_path)

        if server.error is not None:
            print(f"[FAIL] 假 HRR 服务端异常: {server.error}")
            return 1

        if server.connections_served == 0:
            print("[FAIL] 客户端没有连到假 HRR 服务端")
            print(f"[INFO] 客户端退出码: {proc_returncode}")
            if process_output_text:
                print(process_output_text.rstrip())
            if log_text:
                print_tail(log_path, 80)
            return 1

        if not matched:
            print("[FAIL] 客户端日志里没有看到明确的 HRR 拒绝")
            print(f"[INFO] 客户端退出码: {proc_returncode}")
            if process_output_text:
                print(process_output_text.rstrip())
            print_tail(log_path, 80)
            return 1

        if "stage=handshake" not in log_text or "Operation not supported" not in log_text:
            print("[FAIL] 握手失败日志不完整")
            print(f"[INFO] 客户端退出码: {proc_returncode}")
            if process_output_text:
                print(process_output_text.rstrip())
            print_tail(log_path, 80)
            return 1

        print(f"[PASS] 客户端已显式拒绝 HRR，服务端交互次数 {server.connections_served}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
