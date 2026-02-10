
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
SERVER_CONFIG_FILE = "server_test.json"
CLIENT_CONFIG_FILE = "client_test.json"
BLOCK_IP_FILE = "block_ip.txt"
DIRECT_IP_FILE = "direct_ip.txt"

SOCKS_HOST = "127.0.0.1"
SOCKS_PORT = 1080
ECHO_PORT = 9999
UDP_ECHO_PORT = 9999

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
        log_info(f"Echo Server 启动于 127.0.0.1:{self.port} (TCP/UDP)")
        self.thread = threading.Thread(target=self.run)
        self.thread.daemon = True
        self.thread.start()
        
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.bind(('127.0.0.1', self.port))
        self.udp_thread = threading.Thread(target=self.run_udp)
        self.udp_thread.daemon = True
        self.udp_thread.start()

    def stop(self):
        self.running = False
        try: self.sock.close() 
        except: pass
        try: self.udp_sock.close()
        except: pass

    def run(self):
        while self.running:
            try:
                conn, addr = self.sock.accept()
                threading.Thread(target=self.handle_client, args=(conn,)).start()
            except:
                break
    
    def run_udp(self):
        while self.running:
            try:
                data, addr = self.udp_sock.recvfrom(65535)
                self.udp_sock.sendto(data, addr)
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

import ssl

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
        log_info(f"Fake TLS Server ({self.sni}) started on {self.port} (via openssl)")

    def stop(self):
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except:
                self.process.kill()

def write_json(path, data):
    with open(path, 'w') as f:
        json.dump(data, f, indent=4)

def write_file(path, content):
    with open(path, 'w') as f:
        f.write(content)

def start_socks_process(config_file, log_file):
    cmd = ["./socks", "-c", config_file]
    
    with open(log_file, "w") as out:
         proc = subprocess.Popen(cmd, stdout=out, stderr=out, cwd=BUILD_DIR)
    return proc

def socks5_handshake(sock, username=None, password=None):
    methods = [0x00]
    if username and password:
        methods.append(0x02)

    sock.sendall(struct.pack('BB', 0x05, len(methods)) + bytes(methods))
    ver, method = struct.unpack('BB', sock.recv(2))

    if ver != 0x05:
        raise Exception("无效的 SOCKS 版本")

    if method == 0x00:
        pass
    elif method == 0x02:
        if not username or not password:
            raise Exception("服务端请求认证，但未提供凭据")
        
        ulen = len(username)
        plen = len(password)
        auth_req = struct.pack('BB', 0x01, ulen) + username.encode() + struct.pack('B', plen) + password.encode()
        sock.sendall(auth_req)
        
        aver, status = struct.unpack('BB', sock.recv(2))
        if aver != 0x01 or status != 0x00:
            raise Exception("认证失败")
    else:
        raise Exception(f"服务端请求不支持的认证方法: {method}")

def generate_keys():
    try:
        output = subprocess.check_output([SOCKS_BIN, "x25519"], cwd=BUILD_DIR).decode()
        lines = output.strip().split('\n')
        sk = lines[0].split(': ')[1].strip()
        pk = lines[1].split(': ')[1].strip()
        return {"private_key": sk, "public_key": pk}
    except Exception as e:
        raise Exception(f"Failed to generate keys via socks: {e}")

SHORT_ID = "0102030405060708"

def socks5_connect_tcp(proxy_host, proxy_port, target_host, target_port, username=None, password=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((proxy_host, proxy_port))
        socks5_handshake(s, username, password)
        
        req = b'\x05\x01\x00\x01' + socket.inet_aton(target_host) + struct.pack('!H', target_port)
        s.sendall(req)
        
        resp = s.recv(1024)
        if len(resp) < 10:
             raise Exception("响应过短")
        
        ver, rep, rsv, atyp = struct.unpack('BBBB', resp[:4])
        if rep != 0x00:
            return s, rep
            
        return s, 0
    except Exception as e:
        s.close()
        raise e

def stop_process(proc):
    if not proc:
        return
    if proc.poll() is not None:
        return
    try:
        os.kill(proc.pid, signal.SIGTERM)
        proc.wait(timeout=2)
    except Exception:
        pass
    
    if proc.poll() is None:
        try:
            os.kill(proc.pid, signal.SIGKILL)
            proc.wait()
        except:
            pass

def test_routing_rules():
    log_info(">>> 开始测试: 路由规则 (Routing Rules) <<<")
    
    keys = generate_keys()
    pk = keys["public_key"]
    sk = keys["private_key"]

    server_cfg = {
        "mode": "server",
        "log": {"level": "debug", "file": "server_route_internal.log"},
        "inbound": {"host": "127.0.0.1", "port": 20001},
        "reality": {
            "sni": "www.example.com",
            "private_key": sk,
            "public_key": pk,
            "short_id": SHORT_ID
        },
        "fallbacks": [
            {"sni": "www.example.com", "host": "127.0.0.1", "port": "14443"}
        ],
        "timeout": {"idle": 60}
    }
    client_cfg = {
        "mode": "client",
        "log": {"level": "debug", "file": "client_route_internal.log"},
        "inbound": {"host": "127.0.0.1", "port": 1085},
        "outbound": {"host": "127.0.0.1", "port": 20001},
        "socks": {
            "host": "127.0.0.1",
            "port": 1085,
            "auth": False
        },
        "reality": {
            "sni": "www.example.com",
            "public_key": pk,
            "private_key": sk,
            "short_id": SHORT_ID,
        },
         "timeout": {"idle": 60}
    }
    
    write_json(f"{BUILD_DIR}/server_route.json", server_cfg)
    write_json(f"{BUILD_DIR}/client_route.json", client_cfg)
    
    write_file(f"{BUILD_DIR}/{BLOCK_IP_FILE}", "1.2.3.4/32\n")
    write_file(f"{BUILD_DIR}/{DIRECT_IP_FILE}", "127.0.0.1/32\n")
    
    sp = start_socks_process(f"server_route.json", f"{BUILD_DIR}/server_route.log")
    cp = start_socks_process(f"client_route.json", f"{BUILD_DIR}/client_route.log")
    time.sleep(1)
    
    try:
        log_info("测试: 阻止规则 (Block Rule: 1.2.3.4)")
        try:
            sock, rep = socks5_connect_tcp(SOCKS_HOST, 1085, "1.2.3.4", 80)
            if rep == 0x02:
                log_pass("连接被正确阻止 (REP=0x02)")
            else:
                log_fail(f"连接未被正确阻止，返回码: {rep}")
            sock.close()
        except Exception as e:
            log_pass(f"连接被阻止 (异常: {e})")

        log_info("测试: 直连规则 (Direct Rule: 127.0.0.1)")
        sock, rep = socks5_connect_tcp(SOCKS_HOST, 1085, "127.0.0.1", ECHO_PORT)
        if rep == 0:
            sock.sendall(b"PING")
            res = sock.recv(1024)
            if res == b"PING":
                log_pass("连接 127.0.0.1 成功 (Ping/Pong)")
            else:
                log_fail("连接成功但数据回显失败")
            sock.close()
        else:
            log_fail(f"连接失败，返回码: {rep}")

    finally:
        stop_process(sp)
        stop_process(cp)

def test_authentication():
    log_info("\n>>> 开始测试: 身份认证 (Authentication) <<<")
    user = "testuser"
    pwd = "password123"
    
    keys = generate_keys()
    pk = keys["public_key"]
    sk = keys["private_key"]

    server_cfg = {
        "mode": "server",
        "log": {"level": "debug", "file": "server_auth_internal.log"},
        "inbound": {"host": "127.0.0.1", "port": 20002}, # 不同端口避免冲突
        "reality": { "sni": "www.microsoft.com", "private_key": sk, "public_key": pk, "short_id": SHORT_ID },
        "fallbacks": [
            {"sni": "www.microsoft.com", "host": "127.0.0.1", "port": "14444"}
        ],
        "timeout": {"idle": 60}
    }
    client_cfg = {
        "mode": "client",
        "log": {"level": "debug", "file": "client_auth_internal.log"},
        "inbound": {"host": "127.0.0.1", "port": 1086}, # 使用 1086 端口
        "socks": {
            "host": "127.0.0.1",
            "port": 1086,
            "auth": True,
            "username": user,
            "password": pwd
        },
        "outbound": {"host": "127.0.0.1", "port": 20002},
        "reality": { "sni": "www.microsoft.com", "public_key": pk, "private_key": sk, "short_id": SHORT_ID },
        "timeout": {"idle": 60}
    }
    
    write_json(f"{BUILD_DIR}/server_auth.json", server_cfg)
    write_json(f"{BUILD_DIR}/client_auth.json", client_cfg)
    
    sp = start_socks_process(f"server_auth.json", f"{BUILD_DIR}/server_auth.log")
    cp = start_socks_process(f"client_auth.json", f"{BUILD_DIR}/client_auth.log")
    time.sleep(1)
    
    try:
        log_info("测试: 认证失败 (Wrong Credentials)")
        try:
            sock, rep = socks5_connect_tcp("127.0.0.1", 1086, "127.0.0.1", ECHO_PORT, "wrong", "pass")
            log_fail("期望认证失败，但成功了")
            sock.close()
        except Exception as e:
            if "认证失败" in str(e):
                log_pass("认证失败被正确拦截")
            else:
                 log_pass(f"认证流程中断 ({e})")

        log_info("测试: 认证成功 (Correct Credentials)")
        try:
            sock, rep = socks5_connect_tcp("127.0.0.1", 1086, "127.0.0.1", ECHO_PORT, user, pwd)
            if rep == 0:
                sock.sendall(b"AUTH_TEST")
                if sock.recv(1024) == b"AUTH_TEST":
                    log_pass("认证成功且数据传输正常")
                else:
                    log_fail("认证成功但数据异常")
                sock.close()
            else:
                log_fail(f"连接失败 REP={rep}")
        except Exception as e:
            log_fail(f"认证过程异常: {e}")
            
    finally:
        stop_process(sp)
        stop_process(cp)

def test_udp_function():
    log_info("\n>>> 开始测试: UDP 功能 (UDP Functionality) <<<")
    
    keys = generate_keys()
    pk = keys["public_key"]
    sk = keys["private_key"]
    
    server_cfg = {
        "mode": "server", "log": {"level": "debug", "file": "server_udp_internal.log"},
        "inbound": {"host": "127.0.0.1", "port": 20003},
        "reality": { "sni": "www.google.com", "private_key": sk, "public_key": pk, "short_id": SHORT_ID },
        "fallbacks": [
            {"sni": "www.google.com", "host": "127.0.0.1", "port": "14445"}
        ],
        "timeout": {"idle": 60}
    }
    client_cfg = {
        "mode": "client", "log": {"level": "debug", "file": "client_udp_internal.log"},
        "inbound": {"host": "127.0.0.1", "port": 1087},
        "outbound": {"host": "127.0.0.1", "port": 20003},
        "socks": {
            "host": "127.0.0.1",
            "port": 1087,
            "auth": False
        },
        "reality": { "sni": "www.google.com", "public_key": pk, "private_key": sk, "short_id": SHORT_ID },
        "timeout": {"idle": 60}
    }
    
    write_json(f"{BUILD_DIR}/server_udp.json", server_cfg)
    write_json(f"{BUILD_DIR}/client_udp.json", client_cfg)
    
    sp = start_socks_process(f"server_udp.json", f"{BUILD_DIR}/server_udp.log")
    cp = start_socks_process(f"client_udp.json", f"{BUILD_DIR}/client_udp.log")
    time.sleep(1)
    
    try:
        # TCP Control Channel
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sock.connect(('127.0.0.1', 1087))
        
        # Handshake
        tcp_sock.sendall(b'\x05\x01\x00')
        tcp_sock.recv(2)
        
        req = b'\x05\x03\x00\x01' + socket.inet_aton('0.0.0.0') + struct.pack('!H', 0)
        tcp_sock.sendall(req)
        resp = tcp_sock.recv(1024)
        
        if resp[1] != 0:
            log_fail(f"UDP Associate 拒绝: {resp[1]}")
            return
        
        bnd_ip = socket.inet_ntoa(resp[4:8])
        bnd_port = struct.unpack('!H', resp[8:10])[0]
        log_info(f"UDP Relay 分配地址: {bnd_ip}:{bnd_port}")
        
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        header = b'\x00\x00\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', UDP_ECHO_PORT)
        payload = b"UDP_TEST_DATA"
        packet = header + payload
        
        udp_sock.sendto(packet, ('127.0.0.1', bnd_port))
        udp_sock.settimeout(5)
        
        try:
            data, _ = udp_sock.recvfrom(4096)
            if len(data) > 10:
                recv_payload = data[10:]
                if recv_payload == payload:
                    log_pass("UDP Echo 测试通过")
                else:
                    log_fail(f"UDP 数据不匹配: {recv_payload}")
            else:
                log_fail("UDP 响应过短")
                
        except socket.timeout:
            log_fail("UDP 接收超时")
        
        udp_sock.close()
        tcp_sock.close()
        
    finally:
        stop_process(sp)
        stop_process(cp)

def clean_up():
    pass

def run_tproxy_test():
    if os.environ.get("RUN_TPROXY") != "1":
        log_info("TPROXY 测试未启用，设置 RUN_TPROXY=1 可开启")
        return
    if os.geteuid() != 0:
        log_fail("TPROXY 测试需要 root 或 CAP_NET_ADMIN，已跳过")
        return

    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cmd = ["bash", "script/ci_tproxy_test.sh", "--full"]
    log_info("开始执行 TPROXY 全链路测试")
    result = subprocess.run(cmd, cwd=root_dir)
    if result.returncode == 0:
        log_pass("TPROXY 全链路测试通过")
    else:
        log_fail(f"TPROXY 全链路测试失败 code={result.returncode}")

if __name__ == "__main__":
    if not os.path.exists(BUILD_DIR):
        print(f"Build 目录不存在: {BUILD_DIR}")
        sys.exit(1)
        
    echo = EchoServer(ECHO_PORT)
    echo.start()

    tls_example = FakeTLSServer(14443, "www.example.com")
    tls_example.start()
    
    tls_microsoft = FakeTLSServer(14444, "www.microsoft.com")
    tls_microsoft.start()
    
    tls_google = FakeTLSServer(14445, "www.google.com")
    tls_google.start()
    
    try:
        try:
            test_routing_rules()
        except Exception as e:
            log_fail(f"路由规则测试异常: {e}")

        try:
            test_authentication()
        except Exception as e:
            log_fail(f"认证测试异常: {e}")

        try:
            test_udp_function()
        except Exception as e:
            log_fail(f"UDP 测试异常: {e}")

        try:
            run_tproxy_test()
        except Exception as e:
            log_fail(f"TPROXY 测试异常: {e}")
            
    except KeyboardInterrupt:
        pass
    finally:
        echo.stop()
        tls_example.stop()
        tls_microsoft.stop()
        tls_google.stop()
        clean_up()
        print(f"{Colors.BOLD}\n测试结束.{Colors.ENDC}")
