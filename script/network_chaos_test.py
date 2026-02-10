
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

SOCKS_BIN = "./socks"
BUILD_DIR = "./build"
SOCKS_HOST = "127.0.0.1"
SOCKS_PORT = 1090
ECHO_PORT = 9998
CHAOS_INTERFACE = "lo"

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def log_info(msg):
    print(f"{Colors.OKCYAN}[INFO] {msg}{Colors.ENDC}")

def log_pass(msg):
    print(f"{Colors.OKGREEN}[PASS] {msg}{Colors.ENDC}")

def log_fail(msg):
    print(f"{Colors.FAIL}[FAIL] {msg}{Colors.ENDC}")

def log_warn(msg):
    print(f"{Colors.WARNING}[WARN] {msg}{Colors.ENDC}")

HAS_SUDO = False

def check_requirements():
    global HAS_SUDO
    if not shutil.which("tc"):
        log_fail("'tc' (Traffic Control) not found. Please install iproute2.")
        sys.exit(1)
    
    try:
        subprocess.run(["sudo", "-n", "true"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        HAS_SUDO = True
    except subprocess.CalledProcessError:
        log_warn("Passwordless sudo not available. Chaos (tc) commands will be SKIPPED.")
        HAS_SUDO = False

def write_json(path, data):
    with open(path, 'w') as f:
        json.dump(data, f, indent=4)

def generate_keys():
    try:
        output = subprocess.check_output([SOCKS_BIN, "x25519"], cwd=BUILD_DIR).decode()
        lines = output.strip().split('\n')
        sk = lines[0].split(': ')[1].strip()
        pk = lines[1].split(': ')[1].strip()
        return {"private_key": sk, "public_key": pk}
    except Exception as e:
        raise Exception(f"Failed to generate keys via socks: {e}")


def setup_chaos(delay_ms=0, loss_percent=0):
    """
    Applies network chaos to localhost using tc netem.
    WARNING: This affects ALL localhost traffic.
    """
    if not HAS_SUDO:
        log_warn(f"[Simulated] Would apply chaos: Delay={delay_ms}ms, Loss={loss_percent}%")
        return

    cmd_reset = ["sudo", "tc", "qdisc", "del", "dev", CHAOS_INTERFACE, "root"]
    subprocess.run(cmd_reset, stderr=subprocess.DEVNULL, check=False) # Ensure clean state

    if delay_ms == 0 and loss_percent == 0:
        return

    cmd_add = ["sudo", "tc", "qdisc", "add", "dev", CHAOS_INTERFACE, "root", "netem"]
    if delay_ms > 0:
        cmd_add.extend(["delay", f"{delay_ms}ms"])
    if loss_percent > 0:
        cmd_add.extend(["loss", f"{loss_percent}%"])
    
    log_info(f"Applying Chaos: Delay={delay_ms}ms, Loss={loss_percent}% on {CHAOS_INTERFACE}")
    try:
        subprocess.run(cmd_add, check=True)
    except subprocess.CalledProcessError as e:
        log_fail(f"Failed to apply chaos: {e}")
        sys.exit(1)

def clear_chaos():
    if not HAS_SUDO:
        return
    cmd_reset = ["sudo", "tc", "qdisc", "del", "dev", CHAOS_INTERFACE, "root"]
    subprocess.run(cmd_reset, stderr=subprocess.DEVNULL, check=False)
    log_info("Chaos cleared.")

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
        log_info(f"Echo Server started on 127.0.0.1:{self.port}")
        self.thread = threading.Thread(target=self.run)
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        self.running = False
        try: self.sock.close() 
        except: pass

    def run(self):
        while self.running:
            try:
                conn, addr = self.sock.accept()
                threading.Thread(target=self.handle_client, args=(conn,)).start()
            except:
                break

    def handle_client(self, conn):
        try:
            while True:
                data = conn.recv(4096)
                if not data: break
                conn.sendall(data)
        except:
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
        cmd = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", self.key_file, "-out", self.cert_file,
            "-days", "365", "-nodes", "-subj", f"/CN={self.sni}"
        ]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def start(self):
        cmd = [
            "openssl", "s_server",
            "-accept", str(self.port),
            "-cert", self.cert_file,
            "-key", self.key_file,
            "-tls1_3",
            "-quiet",
            "-www"
        ]
        self.process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log_info(f"Fake TLS Server ({self.sni}) started on {self.port}")

    def stop(self):
        if self.process:
            self.process.terminate()
            try: self.process.wait(timeout=2)
            except: self.process.kill()

def socks5_connect_and_transfer(proxy_host, proxy_port, target_host, target_port, data_size=1024*1024):
    """
    Connects via SOCKS5, sends 'data_size' bytes, and verifies echo.
    Returns: (success, duration_seconds)
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    start_time = time.time()
    
    try:
        s.connect((proxy_host, proxy_port))
        
        s.sendall(b'\x05\x01\x00')
        ver, method = struct.unpack('BB', s.recv(2))
        if ver != 0x05 or method != 0x00:
            raise Exception(f"Handshake failed: {ver}, {method}")
            
        req = b'\x05\x01\x00\x01' + socket.inet_aton(target_host) + struct.pack('!H', target_port)
        s.sendall(req)
        
        resp = s.recv(1024)
        if len(resp) < 10 or resp[1] != 0x00:
             raise Exception(f"Connect failed: {resp[1] if len(resp)>1 else 'short'}")
             
        payload = os.urandom(4096)
        total_sent = 0
        total_recv = 0
        
        while total_sent < data_size:
            to_send = min(4096, data_size - total_sent)
            s.sendall(payload[:to_send])
            total_sent += to_send
            
            chunk = s.recv(4096)
            if not chunk:
                raise Exception("Connection closed during transfer")
            total_recv += len(chunk)
            
        while total_recv < total_sent:
             chunk = s.recv(4096)
             if not chunk: break
             total_recv += len(chunk)
             
        if total_recv != total_sent:
            raise Exception(f"Data mismatch: sent {total_sent}, recv {total_recv}")
            
        duration = time.time() - start_time
        return True, duration
        
    except Exception as e:
        log_fail(f"Transfer failed: {e}")
        return False, 0
    finally:
        s.close()

def run_test():
    check_requirements()
    
    echo = EchoServer(ECHO_PORT)
    echo.start()
    
    sni = "chaos.test.com"
    tls = FakeTLSServer(14446, sni)
    tls.start()
    
    keys = generate_keys()
    pk, sk = keys["public_key"], keys["private_key"]
    sid = "0102030405060708"
    
    server_cfg = {
        "mode": "server",
        "log": {"level": "info", "file": "chaos_server.log"},
        "inbound": {"host": "127.0.0.1", "port": 20005},
        "reality": { "sni": sni, "private_key": sk, "public_key": pk, "short_id": sid },
        "fallbacks": [{"sni": sni, "host": "127.0.0.1", "port": "14446"}],
        "timeout": {"idle": 120}
    }
    client_cfg = {
        "mode": "client",
        "log": {"level": "info", "file": "chaos_client.log"},
        "inbound": {"host": "127.0.0.1", "port": SOCKS_PORT},
        "outbound": {"host": "127.0.0.1", "port": 20005},
        "socks": {"host": "127.0.0.1", "port": SOCKS_PORT, "auth": False},
        "reality": { "sni": sni, "public_key": pk, "private_key": sk, "short_id": sid },
        "timeout": {"idle": 120}
    }
    
    write_json(f"{BUILD_DIR}/chaos_server.json", server_cfg)
    write_json(f"{BUILD_DIR}/chaos_client.json", client_cfg)
    
    sp = subprocess.Popen(["./socks", "-c", "chaos_server.json"], cwd=BUILD_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    cp = subprocess.Popen(["./socks", "-c", "chaos_client.json"], cwd=BUILD_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    time.sleep(2)
    
    try:
        log_info("=== Phase 1: Baseline (No Chaos) ===")
        ok, dur = socks5_connect_and_transfer(SOCKS_HOST, SOCKS_PORT, "127.0.0.1", ECHO_PORT, 1024*1024)
        if ok:
            log_pass(f"Baseline transfer successful ({dur:.2f}s)")
        else:
            log_fail("Baseline failed! Aborting.")
            return

        log_info("=== Phase 2: High Latency (200ms) ===")
        setup_chaos(delay_ms=200, loss_percent=0)
        time.sleep(1)
        ok, dur = socks5_connect_and_transfer(SOCKS_HOST, SOCKS_PORT, "127.0.0.1", ECHO_PORT, 100*1024) # Smaller data
        if ok:
            log_pass(f"Latency test successful ({dur:.2f}s)")
        else:
            log_fail("Latency test failed")

        log_info("=== Phase 3: Packet Loss (5%) ===")
        setup_chaos(delay_ms=0, loss_percent=5)
        time.sleep(1)
        ok, dur = socks5_connect_and_transfer(SOCKS_HOST, SOCKS_PORT, "127.0.0.1", ECHO_PORT, 100*1024)
        if ok:
            log_pass(f"Loss test successful ({dur:.2f}s)")
        else:
            log_fail("Loss test failed")
            
        log_info("=== Phase 4: Combined Chaos (100ms + 2% Loss) ===")
        setup_chaos(delay_ms=100, loss_percent=2)
        time.sleep(1)
        ok, dur = socks5_connect_and_transfer(SOCKS_HOST, SOCKS_PORT, "127.0.0.1", ECHO_PORT, 50*1024)
        if ok:
            log_pass(f"Combined test successful ({dur:.2f}s)")
        else:
            log_fail("Combined test failed")

    except KeyboardInterrupt:
        pass
    except Exception as e:
        log_fail(f"Test Exception: {e}")
    finally:
        log_info("Cleaning up...")
        clear_chaos()
        os.kill(sp.pid, signal.SIGTERM)
        os.kill(cp.pid, signal.SIGTERM)
        sp.wait()
        cp.wait()
        echo.stop()
        tls.stop()

if __name__ == "__main__":
    if not os.path.exists(BUILD_DIR):
        print(f"Build directory not found: {BUILD_DIR}")
        sys.exit(1)
    run_test()
