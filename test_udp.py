import socket
import struct
import time
import threading

# 配置
PROXY_HOST = '127.0.0.1'
PROXY_PORT = 1080
DNS_SERVER = '8.8.8.8'
DNS_PORT = 53

def test_udp_associate():
    # 1. 建立 TCP 连接 (控制通道)
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.connect((PROXY_HOST, PROXY_PORT))
    print(f"[TCP] Connected to proxy {PROXY_HOST}:{PROXY_PORT}")

    # 2. SOCKS5 握手 (No Auth)
    tcp_sock.sendall(b'\x05\x01\x00')
    ver, method = struct.unpack('BB', tcp_sock.recv(2))
    if ver != 5 or method != 0:
        print("[TCP] Handshake failed")
        return

    # 3. 发送 UDP ASSOCIATE 请求
    # CMD=0x03 (UDP), ATYP=0x01 (IPv4), ADDR=0.0.0.0, PORT=0
    req = b'\x05\x03\x00\x01' + socket.inet_aton('0.0.0.0') + struct.pack('!H', 0)
    tcp_sock.sendall(req)

    # 4. 接收响应
    # VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
    resp = tcp_sock.recv(1024)
    if resp[1] != 0:
        print(f"[TCP] UDP Associate failed, reply: {resp[1]}")
        return
    
    # 解析代理分配的 UDP 端口
    bnd_ip = socket.inet_ntoa(resp[4:8])
    bnd_port = struct.unpack('!H', resp[8:10])[0]
    print(f"[TCP] Proxy assigned UDP relay: {bnd_ip}:{bnd_port}")

    # 5. 准备 UDP Socket
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # 6. 构造 DNS 查询包 (查询 google.com 的 A 记录)
    # Transaction ID, Flags, Questions, Answer RRs, Auth RRs, Add RRs
    dns_payload = b'\xAA\xAA\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' \
                  b'\x06google\x03com\x00\x00\x01\x00\x01'

    # 7. 构造 SOCKS5 UDP 封装头
    # RSV(2) | FRAG(1) | ATYP(1) | DST.ADDR | DST.PORT | DATA
    # 发送给 8.8.8.8:53
    socks_header = b'\x00\x00\x00\x01' + socket.inet_aton(DNS_SERVER) + struct.pack('!H', DNS_PORT)
    final_packet = socks_header + dns_payload

    print(f"[UDP] Sending DNS query via {bnd_ip}:{bnd_port} to {DNS_SERVER}:{DNS_PORT}")
    udp_sock.sendto(final_packet, (PROXY_HOST, bnd_port)) # 注意：发给 Proxy IP + BND Port

    # 8. 接收响应
    udp_sock.settimeout(5)
    try:
        data, addr = udp_sock.recvfrom(4096)
        print(f"[UDP] Received {len(data)} bytes from proxy")
        
        # 解析响应头
        # 头部长度取决于 ATYP，这里假设返回 IPv4
        # RSV(2) + FRAG(1) + ATYP(1) + IP(4) + Port(2) = 10 bytes
        if len(data) > 10:
            header = data[:10]
            payload = data[10:]
            r_atyp = header[3]
            if r_atyp == 1:
                 r_ip = socket.inet_ntoa(header[4:8])
                 r_port = struct.unpack('!H', header[8:10])[0]
                 print(f"[UDP] Response origin: {r_ip}:{r_port}")
                 print(f"[UDP] DNS payload size: {len(payload)}")
                 if b'\x06google\x03com' in payload:
                     print("[SUCCESS] DNS response contains query domain!")
            else:
                print(f"[UDP] Received non-IPv4 ATYP: {r_atyp}")
    except socket.timeout:
        print("[UDP] Timeout waiting for response")

    # 保持 TCP 连接一小会儿，否则 UDP 映射会被关闭
    time.sleep(1)
    tcp_sock.close()
    udp_sock.close()

if __name__ == '__main__':
    test_udp_associate()
