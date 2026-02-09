
import asyncio
import socket
import struct
import time
import subprocess
import os
import sys
import json
import signal
import resource

SOCKS_BIN = "./socks"
BUILD_DIR = "./build"
SOCKS_HOST = "127.0.0.1"
SOCKS_PORT = 1095
ECHO_PORT = 9995
TARGET_CONCURRENCY = 1000
DURATION = 30

# ANSI Colors
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

def generate_keys():
    try:
        output = subprocess.check_output([SOCKS_BIN, "x25519"], cwd=BUILD_DIR).decode()
        lines = output.strip().split('\n')
        sk = lines[0].split(': ')[1].strip()
        pk = lines[1].split(': ')[1].strip()
        verify = lines[2].split(': ')[1].strip() if len(lines) > 2 and "verify key" in lines[2] else ""
        return {"private_key": sk, "public_key": pk, "verify_public_key": verify}
    except Exception as e:
        raise Exception(f"Failed to generate keys via socks: {e}")

def write_json(path, data):
    with open(path, 'w') as f:
        json.dump(data, f, indent=4)

async def start_echo_server(port):
    async def handle_echo(reader, writer):
        try:
            while True:
                data = await reader.read(1024)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except:
            pass
        finally:
            writer.close()
            try: await writer.wait_closed()
            except: pass

    server = await asyncio.start_server(handle_echo, '127.0.0.1', port)
    log_info(f"Async Echo Server started on 127.0.0.1:{port}")
    return server

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

async def connect_socks5(socks_host, socks_port, target_host, target_port):
    try:
        reader, writer = await asyncio.open_connection(socks_host, socks_port)
        
        writer.write(b'\x05\x01\x00')
        await writer.drain()
        auth_resp = await reader.read(2)
        if len(auth_resp) < 2 or auth_resp[1] != 0x00:
            return None, None

        req = b'\x05\x01\x00\x01' + socket.inet_aton(target_host) + struct.pack('!H', target_port)
        writer.write(req)
        await writer.drain()
        
        resp = await reader.read(1024)
        if len(resp) < 10 or resp[1] != 0x00:
            return None, None
            
        return reader, writer
    except Exception:
        return None, None

async def worker(idx, stats):
    try:
        reader, writer = await connect_socks5(SOCKS_HOST, SOCKS_PORT, "127.0.0.1", ECHO_PORT)
        if reader and writer:
            stats['connected'] += 1
            try:
                writer.write(b'PING')
                await writer.drain()
                data = await reader.read(4)
                if data == b'PING':
                    await asyncio.sleep(DURATION)
            except:
                pass
            finally:
                writer.close()
                try: await writer.wait_closed()
                except: pass
        else:
            stats['failed'] += 1
    except:
        stats['failed'] += 1

async def monitor_memory(pid, stop_event):
    log_info(f"Monitoring memory for PID {pid}...")
    peak_rss = 0
    while not stop_event.is_set():
        try:
            with open(f"/proc/{pid}/statm") as f:
                pass
            
            res = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True)
            if res.returncode == 0:
                rss_kb = int(res.stdout.strip())
                if rss_kb > peak_rss:
                    peak_rss = rss_kb
        except:
            pass
        await asyncio.sleep(1)
    
    log_info(f"Peak RSS Memory: {peak_rss / 1024:.2f} MB")

async def run_stress_test():
    tls = FakeTLSServer(14447, "stress.test.com")
    tls.start()
    
    echo_server = await start_echo_server(ECHO_PORT)
    
    keys = generate_keys()
    pk, sk, vk = keys["public_key"], keys["private_key"], keys["verify_public_key"]
    sid = "0102030405060708"
    
    server_cfg = {
        "mode": "server", "log": {"level": "warn", "file": "stress_server.log"}, # Warn level to reduce IO
        "inbound": {"host": "127.0.0.1", "port": 20006},
        "reality": { "sni": "stress.test.com", "private_key": sk, "public_key": pk, "short_id": sid },
        "fallbacks": [{"sni": "stress.test.com", "host": "127.0.0.1", "port": "14447"}],
        "timeout": {"idle": 120},
        "limits": {"max_connections": 20000} # Ensure limit is high enough
    }
    client_cfg = {
        "mode": "client", "log": {"level": "warn", "file": "stress_client.log"},
        "inbound": {"host": "127.0.0.1", "port": SOCKS_PORT},
        "outbound": {"host": "127.0.0.1", "port": 20006},
        "socks": {"host": "127.0.0.1", "port": SOCKS_PORT, "auth": False},
        "reality": { "sni": "stress.test.com", "public_key": pk, "private_key": sk, "short_id": sid, "verify_public_key": vk },
        "timeout": {"idle": 120},
        "limits": {"max_connections": 20000}
    }
    
    write_json(f"{BUILD_DIR}/stress_server.json", server_cfg)
    write_json(f"{BUILD_DIR}/stress_client.json", client_cfg)
    
    sp = subprocess.Popen(["./socks", "-c", "stress_server.json"], cwd=BUILD_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    cp = subprocess.Popen(["./socks", "-c", "stress_client.json"], cwd=BUILD_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    time.sleep(2)
    
    stop_monitor = asyncio.Event()
    mon_task = asyncio.create_task(monitor_memory(sp.pid, stop_monitor))
    
    log_info(f"Launching {TARGET_CONCURRENCY} connections...")
    stats = {'connected': 0, 'failed': 0}
    
    tasks = []
    batch_size = 100
    for i in range(0, TARGET_CONCURRENCY, batch_size):
        batch = [asyncio.create_task(worker(j, stats)) for j in range(i, min(i+batch_size, TARGET_CONCURRENCY))]
        tasks.extend(batch)
        await asyncio.sleep(0.1)
        
    log_info("All connection tasks launched. Waiting...")
    
    await asyncio.gather(*tasks)
    
    stop_monitor.set()
    await mon_task
    
    log_pass(f"Test Finished. Connected: {stats['connected']}, Failed: {stats['failed']}")
    if stats['connected'] > TARGET_CONCURRENCY * 0.95:
        log_pass("Stress Test Passed (>95% success)")
    else:
        log_fail("Stress Test Failed")

    os.kill(sp.pid, signal.SIGTERM)
    os.kill(cp.pid, signal.SIGTERM)
    sp.wait()
    cp.wait()
    tls.stop()
    echo_server.close()
    await echo_server.wait_closed()

if __name__ == "__main__":
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
        print(f"Raised open file limit to {hard}")
    except ValueError:
        print("Could not raise file limit")

    if not os.path.exists(BUILD_DIR):
        print(f"Build directory not found: {BUILD_DIR}")
        sys.exit(1)
        
    try:
        asyncio.run(run_stress_test())
    except KeyboardInterrupt:
        pass
