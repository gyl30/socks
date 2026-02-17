import argparse
import socket
import struct
import time
import threading
import subprocess
import os
import sys
import json
import signal
import shutil
import re

SOCKS_BIN = "./socks"
BUILD_DIR = "./build"
SHORT_ID = "0102030405060708"

class Colors:
    HEADER = '\033[95m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

def log_info(msg):
    print(f"{Colors.OKCYAN}[INFO] {msg}{Colors.ENDC}")

def log_pass(msg):
    print(f"{Colors.OKGREEN}[PASS] {msg}{Colors.ENDC}")

def log_fail(msg):
    print(f"{Colors.FAIL}[FAIL] {msg}{Colors.ENDC}")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Run valgrind memory safety test against socks client/server.")
    parser.add_argument("--build-dir", default="./build", help="Build directory that contains the socks binary.")
    parser.add_argument("--socks-bin", default="./socks", help="Path to socks binary relative to --build-dir.")
    parser.add_argument("--traffic-count", type=int, default=5, help="Number of extra short SOCKS connections.")
    parser.add_argument("--server-ready-timeout", type=int, default=20, help="Timeout seconds waiting for server inbound to become ready.")
    parser.add_argument("--client-ready-timeout", type=int, default=90, help="Timeout seconds waiting for client socks to become ready.")
    parser.add_argument("--self-test-args", action="store_true", help="Run argument parsing regression checks and exit.")
    return parser.parse_args(argv)


def run_arg_parse_regression_test():
    default_args = parse_args([])
    default_ok = (
        default_args.traffic_count == 5
        and default_args.server_ready_timeout == 20
        and default_args.client_ready_timeout == 90
        and default_args.self_test_args is False
    )
    if not default_ok:
        log_fail("arg defaults mismatch")
        return False

    custom_args = parse_args([
        "--traffic-count", "9",
        "--server-ready-timeout", "31",
        "--client-ready-timeout", "123",
    ])
    custom_ok = (
        custom_args.traffic_count == 9
        and custom_args.server_ready_timeout == 31
        and custom_args.client_ready_timeout == 123
        and custom_args.self_test_args is False
    )
    if not custom_ok:
        log_fail("arg custom values mismatch")
        return False

    log_pass("arg regression checks passed")
    return True


def pick_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for_tcp_ready(host, port, timeout_sec, name, proc=None):
    deadline = time.time() + timeout_sec
    last_error = None
    while time.time() < deadline:
        if proc is not None and proc.poll() is not None:
            raise RuntimeError(f"{name} exited early with code {proc.returncode}")
        try:
            with socket.create_connection((host, port), timeout=0.3):
                return
        except OSError as e:
            last_error = e
            time.sleep(0.1)
    raise RuntimeError(f"timeout waiting {name} on {host}:{port} last_error={last_error}")


def stop_process(proc):
    if proc is None or proc.poll() is not None:
        return
    # Prefer graceful shutdown path in socks (handled by SIGINT/SIGTERM),
    # so valgrind sees a full teardown instead of abrupt process termination.
    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError(f"socket closed while waiting {size} bytes")
        data.extend(chunk)
    return bytes(data)

class EchoServer:
    def __init__(self, port):
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.running = False
        self.thread = None

    def start(self):
        self.running = True
        self.sock.bind(('127.0.0.1', self.port))
        self.sock.listen(5)
        self.thread = threading.Thread(target=self.run)
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        self.running = False
        try:
            self.sock.close()
        except Exception:
            pass
        if self.thread is not None:
            self.thread.join(timeout=2)

    def run(self):
        while self.running:
            try:
                conn, _addr = self.sock.accept()
                threading.Thread(target=self.handle_client, args=(conn,)).start()
            except Exception:
                break

    def handle_client(self, conn):
        try:
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                conn.sendall(data)
        except Exception:
            pass
        finally:
            conn.close()

class FakeTLSServer:
    def __init__(self, port, sni):
        self.port = port
        self.sni = sni
        self.process = None
        self.cert_file = f"{BUILD_DIR}/{sni}.crt"
        self.key_file = f"{BUILD_DIR}/{sni}.key"
        self.generate_cert()

    def generate_cert(self):
        cmd = ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", self.key_file, "-out", self.cert_file, "-days", "365", "-nodes", "-subj", f"/CN={self.sni}"]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def start(self):
        cmd = ["openssl", "s_server", "-accept", str(self.port), "-cert", self.cert_file, "-key", self.key_file, "-tls1_3", "-quiet", "-www"]
        self.process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def stop(self):
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except Exception:
                self.process.kill()

def write_json(path, data):
    with open(path, 'w') as f:
        json.dump(data, f, indent=4)

def write_file(path, content):
    with open(path, 'w') as f:
        f.write(content)

def generate_keys():
    try:
        output = subprocess.check_output([SOCKS_BIN, "x25519"], cwd=BUILD_DIR).decode()
        lines = output.strip().split('\n')
        sk = lines[0].split(': ')[1].strip()
        pk = lines[1].split(': ')[1].strip()
        return {"private_key": sk, "public_key": pk}
    except Exception as e:
        raise Exception(f"Failed to generate keys: {e}")

def start_socks_process_valgrind(config_file, log_file, name):
    valgrind_log = f"{name}_valgrind.log"
    cmd = [
        "valgrind",
        "--leak-check=full",
        "--show-leak-kinds=all",
        "--track-origins=yes",
        "--error-exitcode=1",
        f"--log-file={valgrind_log}",
        SOCKS_BIN, "-c", config_file
    ]
    
    with open(log_file, "w") as out:
         proc = subprocess.Popen(cmd, stdout=out, stderr=out, cwd=BUILD_DIR)
    return proc, valgrind_log

def socks5_connect(proxy_port, target_host, target_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(15)
    s.connect(('127.0.0.1', proxy_port))
    s.sendall(b'\x05\x01\x00')
    method_resp = recv_exact(s, 2)
    if method_resp != b'\x05\x00':
        raise Exception(f"SOCKS method negotiation failed: {method_resp!r}")
    req = b'\x05\x01\x00\x01' + socket.inet_aton(target_host) + struct.pack('!H', target_port)
    s.sendall(req)
    resp = recv_exact(s, 10)
    if len(resp) < 10 or resp[1] != 0:
        raise Exception("Connect failed")
    return s


def wait_for_proxy_data_path(proxy_port, target_host, target_port, timeout_sec):
    deadline = time.time() + timeout_sec
    last_error = None
    while time.time() < deadline:
        sock = None
        try:
            sock = socks5_connect(proxy_port, target_host, target_port)
            probe = b"READY_CHECK"
            sock.sendall(probe)
            got = recv_exact(sock, len(probe))
            if got == probe:
                return
            last_error = RuntimeError(f"probe mismatch expected={probe!r} got={got!r}")
        except Exception as e:
            last_error = e
            time.sleep(0.5)
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
    raise RuntimeError(f"timeout waiting end-to-end socks path last_error={last_error}")

def analyze_valgrind_log(path, display_name):
    if not os.path.exists(path):
        log_fail(f"{display_name}: log not found {path}")
        return False

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    error_summary_ok = re.search(r"ERROR SUMMARY:\s+0 errors from 0 contexts", content) is not None
    lost_summary_ok = all(
        re.search(pattern, content) is not None
        for pattern in (
            r"definitely lost:\s+0 bytes in 0 blocks",
            r"indirectly lost:\s+0 bytes in 0 blocks",
            r"possibly lost:\s+0 bytes in 0 blocks",
        )
    )
    all_freed_ok = "All heap blocks were freed -- no leaks are possible" in content

    if error_summary_ok and (lost_summary_ok or all_freed_ok):
        log_pass(f"{display_name}: no valgrind errors and no leaks")
        return True

    log_fail(f"{display_name}: valgrind errors or leaks detected")
    for line in content.splitlines():
        stripped = line.strip()
        if "ERROR SUMMARY:" in stripped or "definitely lost:" in stripped or "indirectly lost:" in stripped or "possibly lost:" in stripped:
            print(f"  {stripped}")
    return False


def run_valgrind_test(traffic_count, server_ready_timeout, client_ready_timeout):
    log_info("Starting Valgrind Memory Test...")

    echo_port = pick_free_port()
    tls_port = pick_free_port()
    server_port = pick_free_port()
    client_socks_port = pick_free_port()

    echo = EchoServer(echo_port)
    echo.start()
    tls = FakeTLSServer(tls_port, "valgrind.test.com")
    tls.start()
    wait_for_tcp_ready("127.0.0.1", tls_port, 10, "fake tls server", tls.process)

    keys = generate_keys()

    server_cfg = {
        "mode": "server", "log": {"level": "info", "file": "val_server.log"},
        "inbound": {"host": "127.0.0.1", "port": server_port},
        "reality": { "sni": "valgrind.test.com", "private_key": keys["private_key"], "public_key": keys["public_key"], "short_id": SHORT_ID },
        "fallbacks": [{"sni": "valgrind.test.com", "host": "127.0.0.1", "port": str(tls_port)}],
        "timeout": {"idle": 10}
    }
    client_cfg = {
        "mode": "client", "log": {"level": "info", "file": "val_client.log"},
        "inbound": {"host": "127.0.0.1", "port": client_socks_port},
        "outbound": {"host": "127.0.0.1", "port": server_port},
        "socks": {"host": "127.0.0.1", "port": client_socks_port, "auth": False},
        "reality": { "sni": "valgrind.test.com", "public_key": keys["public_key"], "private_key": keys["private_key"], "short_id": SHORT_ID, "strict_cert_verify": False },
        "timeout": {"idle": 10}
    }

    write_json(f"{BUILD_DIR}/val_server.json", server_cfg)
    write_json(f"{BUILD_DIR}/val_client.json", client_cfg)

    sp, s_vlog = start_socks_process_valgrind("val_server.json", f"{BUILD_DIR}/val_server_stdout.log", "server")
    wait_for_tcp_ready("127.0.0.1", server_port, server_ready_timeout, "server inbound", sp)

    cp, c_vlog = start_socks_process_valgrind("val_client.json", f"{BUILD_DIR}/val_client_stdout.log", "client")
    wait_for_tcp_ready("127.0.0.1", client_socks_port, client_ready_timeout, "client socks", cp)
    wait_for_proxy_data_path(
        client_socks_port,
        "127.0.0.1",
        echo_port,
        max(30, server_ready_timeout, client_ready_timeout),
    )

    success = True

    try:
        log_info("Running traffic...")
        sock = socks5_connect(client_socks_port, "127.0.0.1", echo_port)
        sock.sendall(b"MEMORY_TEST")
        res = sock.recv(1024)
        if res == b"MEMORY_TEST":
            log_pass("Traffic success")
        else:
            log_fail("Traffic mismatch")
            success = False
        sock.close()

        for _ in range(traffic_count):
            sock = socks5_connect(client_socks_port, "127.0.0.1", echo_port)
            sock.close()
            time.sleep(0.1)

    except Exception as e:
        log_fail(f"Test Error: {e}")
        success = False
    finally:
        log_info("Stopping processes...")
        stop_process(cp)
        stop_process(sp)
        echo.stop()
        tls.stop()

    server_rc = sp.wait(timeout=5)
    client_rc = cp.wait(timeout=5)
    if server_rc != 0:
        log_fail(f"server process exit code={server_rc}")
        success = False
    if client_rc != 0:
        log_fail(f"client process exit code={client_rc}")
        success = False
        
    log_info("Analyzing Valgrind Logs...")
    success = analyze_valgrind_log(f"{BUILD_DIR}/{s_vlog}", s_vlog) and success
    success = analyze_valgrind_log(f"{BUILD_DIR}/{c_vlog}", c_vlog) and success
    return success


if __name__ == "__main__":
    args = parse_args()
    if args.self_test_args:
        ok = run_arg_parse_regression_test()
        sys.exit(0 if ok else 1)

    if shutil.which("valgrind") is None:
        print("[FAIL] valgrind is not installed")
        sys.exit(1)

    BUILD_DIR = args.build_dir
    SOCKS_BIN = args.socks_bin

    ok = run_valgrind_test(args.traffic_count, args.server_ready_timeout, args.client_ready_timeout)
    sys.exit(0 if ok else 1)
