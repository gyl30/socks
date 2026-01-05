import socket
import threading
import time
import struct
import random
import string
import sys

# 配置
SOCKS_HOST = '127.0.0.1'
SOCKS_PORT = 1080
ECHO_SERVER_PORT = 8888
CONCURRENCY = 5000        # 并发线程数
DATA_SIZE = 1024 * 100   # 每个线程发送的数据量 (10KB)

# 统计
success_count = 0
fail_count = 0
lock = threading.Lock()

def start_echo_server():
    """启动一个简单的回显服务器，用于作为测试目标"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', ECHO_SERVER_PORT))
    server.listen(1000)
    print(f"[*] Echo Server listening on 127.0.0.1:{ECHO_SERVER_PORT}")
    
    def handle_client(conn):
        try:
            while True:
                data = conn.recv(4096)
                if not data: break
                conn.sendall(data) # 收到什么发回什么
        except:
            pass
        finally:
            conn.close()

    while True:
        client, _ = server.accept()
        t = threading.Thread(target=handle_client, args=(client,))
        t.daemon = True
        t.start()

def socks5_connect(sock, target_ip, target_port):
    """手动实现 SOCKS5 握手"""
    # 1. 认证协商
    sock.sendall(b'\x05\x01\x00')
    resp = sock.recv(2)
    if resp != b'\x05\x00':
        raise Exception(f"Auth failed: {resp}")

    # 2. 连接请求 (CONNECT 127.0.0.1:8888)
    # CMD=0x01, ATYP=0x01 (IPv4)
    ip_bytes = socket.inet_aton(target_ip)
    port_bytes = struct.pack('!H', target_port)
    req = b'\x05\x01\x00\x01' + ip_bytes + port_bytes
    sock.sendall(req)

    # 3. 读取响应
    resp = sock.recv(10) # 简化的读取，实际应该是变长的，但IPv4响应固定是10字节
    if len(resp) < 10 or resp[1] != 0x00:
        raise Exception(f"Connect failed: {resp}")

def worker(idx):
    global success_count, fail_count
    
    # 生成该线程独有的随机数据模式
    # 如果发生串流（数据跑到别的Stream去），校验就会失败
    pattern = f"[{idx:03d}]" + ''.join(random.choices(string.ascii_letters + string.digits, k=20))
    payload = (pattern * (DATA_SIZE // len(pattern))).encode('utf-8')
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10) # 设置超时
        s.connect((SOCKS_HOST, SOCKS_PORT))
        
        # 通过 Socks5 连接到 Echo Server
        socks5_connect(s, '127.0.0.1', ECHO_SERVER_PORT)
        
        # 发送数据
        total_sent = 0
        while total_sent < len(payload):
            sent = s.send(payload[total_sent:])
            if sent == 0: raise Exception("Socket closed during send")
            total_sent += sent
            
        # 接收回显数据
        received = b""
        while len(received) < len(payload):
            chunk = s.recv(4096)
            if not chunk: break
            received += chunk
            
        s.close()

        # 校验数据完整性
        if received != payload:
            raise Exception(f"Data mismatch! Len sent={len(payload)}, recv={len(received)}")
        
        with lock:
            success_count += 1
            # print(f"Worker {idx} OK") # 减少刷屏，只打印结果

    except Exception as e:
        with lock:
            fail_count += 1
        print(f"Worker {idx} FAILED: {e}")

def run_test():
    # 1. 启动 Echo Server (后台运行)
    t_server = threading.Thread(target=start_echo_server)
    t_server.daemon = True
    t_server.start()
    time.sleep(1) # 等待启动

    print(f"[*] Starting {CONCURRENCY} concurrent connections via Socks5...")
    
    threads = []
    start_time = time.time()
    
    for i in range(CONCURRENCY):
        t = threading.Thread(target=worker, args=(i,))
        threads.append(t)
        t.start()
        
    for t in threads:
        t.join()
        
    duration = time.time() - start_time
    print(f"\n[=] Test Finished in {duration:.2f}s")
    print(f"[+] Success: {success_count}")
    print(f"[-] Failed:  {fail_count}")

    if fail_count == 0:
        print("\n✅ Mux Logic Verified: Parallel Integrity Check Passed!")
    else:
        print("\n❌ Mux Logic Issues Found!")

if __name__ == "__main__":
    run_test()
