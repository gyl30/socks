import subprocess
import time
import socket
import struct
import threading
import os
import signal
import sys

# Generate keys dynamically
try:
    output = subprocess.check_output(["./build/socks", "x25519"]).decode()
    # Output format:
    # Private Key: <hex>
    # Public Key:  <hex>
    lines = output.strip().split('\n')
    SERVER_KEY = lines[0].split(': ')[1].strip()
    SERVER_PUB = lines[1].split(': ')[1].strip()
    print(f"Generated Keys:\nPriv: {SERVER_KEY}\nPub:  {SERVER_PUB}")
except Exception as e:
    print(f"Failed to generate keys: {e}")
    sys.exit(1)

# Ports
SERVER_PORT = 30446
CLIENT_SOCKS_PORT = 10803
ECHO_PORT = 30083

def start_echo_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', ECHO_PORT))
    s.listen(1)
    
    def handle_client(conn):
        while True:
            data = conn.recv(1024)
            if not data: break
            conn.sendall(data)
        conn.close()

    t = threading.Thread(target=lambda: handle_client(s.accept()[0]), daemon=True)
    t.start()
    return s

def write_configs():
    server_conf = f"""
{{
    "mode": "server",
    "inbound": {{
        "port": {SERVER_PORT}
    }},
    "reality": {{
        "sni": "www.google.com",
        "private_key": "{SERVER_KEY}",
        "public_key": ""
    }},
    "log": {{
        "level": "debug"
    }},
    "limits": {{
        "max_connections": 5
    }}
}}
"""
    client_conf = f"""
{{
    "mode": "client",
    "log": {{
        "level": "debug"
    }},
    "outbound": {{
         "host": "127.0.0.1",
         "port": {SERVER_PORT}
    }},
    "socks": {{
         "port": {CLIENT_SOCKS_PORT}
    }},
    "reality": {{
        "sni": "www.google.com",
        "public_key": "{SERVER_PUB}"
    }},
    "limits": {{
        "max_connections": 2
    }}
}}
"""
    with open("server_test.json", "w") as f: f.write(server_conf)
    with open("client_test.json", "w") as f: f.write(client_conf)

def socks5_handshake_and_echo():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Retry connect
        for i in range(30):
            try:
                s.connect(('127.0.0.1', CLIENT_SOCKS_PORT))
                print(f"PYTHON: Connected to SOCKS port on retry {i}")
                break
            except ConnectionRefusedError:
                print(f"PYTHON: Connection refused on retry {i}, waiting...")
                time.sleep(1)
        else:
             print("Failed to connect to SOCKS port after retries")
             return False

        # 1. Version identifier/method selection message
        # Ver: 5, NMethods: 1, Methods: [0 (No Auth)]
        s.sendall(b'\x05\x01\x00')
        resp = s.recv(2)
        if resp != b'\x05\x00':
            print(f"Auth handshake failed: {resp.hex()}")
            return False
            
        # 2. Request details
        # Ver: 5, Cmd: 1 (Connect), Rsv: 0, Atyp: 1 (IPv4)
        req = b'\x05\x01\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack("!H", ECHO_PORT)
        s.sendall(req)
        
        resp = s.recv(10) # 10 bytes for IPv4 response
        if len(resp) < 10 or resp[1] != 0x00:
            print(f"Connect failed: {resp.hex()}")
            return False
            
        # 3. Data Transfer
        msg = b"Hello Functional World"
        s.sendall(msg)
        echo = s.recv(len(msg))
        
        if echo != msg:
            print(f"Echo mismatch: {echo} != {msg}")
            return False
            
        print("SOCKS5 Echo Test Passed!")
        s.close()
        return True
    except Exception as e:
        print(f"Test Exception: {e}")
        return False

def main():
    write_configs()
    echo_server = start_echo_server()
    
    # Start Server
    server_proc = subprocess.Popen(["./build/socks", "-c", "server_test.json"], stdout=sys.stdout, stderr=sys.stderr)
    time.sleep(1) # Wait startup
    
    # Start Client
    client_proc = subprocess.Popen(["./build/socks", "-c", "client_test.json"], stdout=sys.stdout, stderr=sys.stderr)
    time.sleep(2) # Wait connection
    
    success = False
    try:
        success = socks5_handshake_and_echo()
    finally:
        server_proc.terminate()
        client_proc.terminate()
        server_proc.wait()
        client_proc.wait()
        if os.path.exists("server_test.json"): os.remove("server_test.json")
        if os.path.exists("client_test.json"): os.remove("client_test.json")

    if success:
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
