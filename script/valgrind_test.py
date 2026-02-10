
import socket
import struct
import time
import threading
import subprocess
import os
import sys
import json
import signal

SOCKS_BIN = "./socks"
BUILD_DIR = "./build"
ECHO_PORT = 9997
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
                data = conn.recv(1024)
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
        cmd = ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", self.key_file, "-out", self.cert_file, "-days", "365", "-nodes", "-subj", f"/CN={self.sni}"]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def start(self):
        cmd = ["openssl", "s_server", "-accept", str(self.port), "-cert", self.cert_file, "-key", self.key_file, "-tls1_3", "-quiet", "-www"]
        self.process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def stop(self):
        if self.process:
            self.process.terminate()
            try: self.process.wait(timeout=2)
            except: self.process.kill()

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
        "./socks", "-c", config_file
    ]
    
    with open(log_file, "w") as out:
         proc = subprocess.Popen(cmd, stdout=out, stderr=out, cwd=BUILD_DIR)
    return proc, valgrind_log

def socks5_connect(proxy_port, target_host, target_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(('127.0.0.1', proxy_port))
    s.sendall(b'\x05\x01\x00')
    s.recv(2)
    req = b'\x05\x01\x00\x01' + socket.inet_aton(target_host) + struct.pack('!H', target_port)
    s.sendall(req)
    resp = s.recv(1024)
    if len(resp) < 10 or resp[1] != 0:
        raise Exception("Connect failed")
    return s

def run_valgrind_test():
    log_info("Starting Valgrind Memory Test...")
    
    echo = EchoServer(ECHO_PORT)
    echo.start()
    tls = FakeTLSServer(14448, "valgrind.test.com")
    tls.start()
    
    keys = generate_keys()
    
    server_cfg = {
        "mode": "server", "log": {"level": "info", "file": "val_server.log"},
        "inbound": {"host": "127.0.0.1", "port": 20008},
        "reality": { "sni": "valgrind.test.com", "private_key": keys["private_key"], "public_key": keys["public_key"], "short_id": SHORT_ID },
        "fallbacks": [{"sni": "valgrind.test.com", "host": "127.0.0.1", "port": "14448"}],
        "timeout": {"idle": 10}
    }
    client_cfg = {
        "mode": "client", "log": {"level": "info", "file": "val_client.log"},
        "inbound": {"host": "127.0.0.1", "port": 1098},
        "outbound": {"host": "127.0.0.1", "port": 20008},
        "socks": {"host": "127.0.0.1", "port": 1098, "auth": False},
        "reality": { "sni": "valgrind.test.com", "public_key": keys["public_key"], "private_key": keys["private_key"], "short_id": SHORT_ID },
        "timeout": {"idle": 10}
    }
    
    write_json(f"{BUILD_DIR}/val_server.json", server_cfg)
    write_json(f"{BUILD_DIR}/val_client.json", client_cfg)
    
    sp, s_vlog = start_socks_process_valgrind("val_server.json", f"{BUILD_DIR}/val_server_stdout.log", "server")
    cp, c_vlog = start_socks_process_valgrind("val_client.json", f"{BUILD_DIR}/val_client_stdout.log", "client")
    
    time.sleep(5)
    
    try:
        log_info("Running traffic...")
        sock = socks5_connect(1098, "127.0.0.1", ECHO_PORT)
        sock.sendall(b"MEMORY_TEST")
        res = sock.recv(1024)
        if res == b"MEMORY_TEST":
            log_pass("Traffic success")
        else:
            log_fail("Traffic mismatch")
        sock.close()
        
        for i in range(5):
            sock = socks5_connect(1098, "127.0.0.1", ECHO_PORT)
            sock.close()
            time.sleep(0.1)
            
    except Exception as e:
        log_fail(f"Test Error: {e}")
    finally:
        log_info("Stopping processes...")
        os.kill(sp.pid, signal.SIGTERM)
        os.kill(cp.pid, signal.SIGTERM)
        sp.wait()
        cp.wait()
        echo.stop()
        tls.stop()
        
    log_info("Analyzing Valgrind Logs...")
    for vlog in [s_vlog, c_vlog]:
        path = f"{BUILD_DIR}/{vlog}"
        if os.path.exists(path):
            with open(path, 'r') as f:
                content = f.read()
                if "definitely lost: 0 bytes in 0 blocks" in content:
                    log_pass(f"{vlog}: No definite leaks")
                else:
                    log_fail(f"{vlog}: LEAKS DETECTED or Valgrind Error!")
                    for line in content.split('\n'):
                        if "definitely lost:" in line or "indirectly lost:" in line or "possibly lost:" in line:
                            print(f"  {line.strip()}")
        else:
            log_fail(f"{vlog} not found!")

if __name__ == "__main__":
    run_valgrind_test()
