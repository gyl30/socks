import subprocess
import time
import socket
import struct
import threading
import os
import sys
from contextlib import ExitStack

# Ports
SERVER_PORT = 30446
CLIENT_SOCKS_PORT = 10803
ECHO_PORT = 30083
SHORT_ID = "0102030405060708"


def generate_keys():
    result = subprocess.run(["./build/socks", "x25519"], capture_output=True, text=True)
    if result.returncode != 0:
        print("Failed to generate keys")
        if result.stderr:
            print(result.stderr.strip())
        return None, None

    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if len(lines) < 2:
        print(f"Unexpected key generation output: {result.stdout!r}")
        return None, None

    key_parts = lines[0].split(":", 1)
    pub_parts = lines[1].split(":", 1)
    if len(key_parts) != 2 or len(pub_parts) != 2:
        print(f"Malformed key generation output: {result.stdout!r}")
        return None, None

    server_key = key_parts[1].strip()
    server_pub = pub_parts[1].strip()
    if not server_key or not server_pub:
        print(f"Empty key detected in output: {result.stdout!r}")
        return None, None
    return server_key, server_pub


def terminate_process(proc):
    if proc.poll() is None:
        proc.terminate()
    deadline = time.monotonic() + 5
    while proc.poll() is None and time.monotonic() < deadline:
        time.sleep(0.05)
    if proc.poll() is None:
        proc.kill()
    while proc.poll() is None:
        time.sleep(0.05)


def remove_file(path):
    if os.path.exists(path):
        os.remove(path)


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


def write_configs(server_key, server_pub):
    server_conf = f"""
{{
    "mode": "server",
    "inbound": {{
        "port": {SERVER_PORT}
    }},
    "reality": {{
        "sni": "www.google.com",
        "private_key": "{server_key}",
        "public_key": "",
        "short_id": "{SHORT_ID}"
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
        "public_key": "{server_pub}",
        "short_id": "{SHORT_ID}"
    }},
    "limits": {{
        "max_connections": 2
    }}
}}
"""
    with open("server_test.json", "w") as f: f.write(server_conf)
    with open("client_test.json", "w") as f: f.write(client_conf)

def socks5_handshake_and_echo():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    connected = False
    for i in range(30):
        rc = s.connect_ex(('127.0.0.1', CLIENT_SOCKS_PORT))
        if rc == 0:
            print(f"PYTHON: Connected to SOCKS port on retry {i}")
            connected = True
            break
        print(f"PYTHON: connect_ex rc={rc} on retry {i}, waiting...")
        time.sleep(1)

    if not connected:
        print("Failed to connect to SOCKS port after retries")
        s.close()
        return False

    # 1. Version identifier/method selection message
    # Ver: 5, NMethods: 1, Methods: [0 (No Auth)]
    s.sendall(b'\x05\x01\x00')
    resp = s.recv(2)
    if resp != b'\x05\x00':
        print(f"Auth handshake failed: {resp.hex()}")
        s.close()
        return False

    # 2. Request details
    # Ver: 5, Cmd: 1 (Connect), Rsv: 0, Atyp: 1 (IPv4)
    req = b'\x05\x01\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack("!H", ECHO_PORT)
    s.sendall(req)

    resp = s.recv(10)  # 10 bytes for IPv4 response
    if len(resp) < 10 or resp[1] != 0x00:
        print(f"Connect failed: {resp.hex()}")
        s.close()
        return False

    # 3. Data Transfer
    msg = b"Hello Functional World"
    s.sendall(msg)
    echo = s.recv(len(msg))

    if echo != msg:
        print(f"Echo mismatch: {echo} != {msg}")
        s.close()
        return False

    print("SOCKS5 Echo Test Passed!")
    s.close()
    return True

def main():
    server_key, server_pub = generate_keys()
    if not server_key or not server_pub:
        sys.exit(1)

    write_configs(server_key, server_pub)
    success = False
    with ExitStack() as cleanup:
        cleanup.callback(remove_file, "server_test.json")
        cleanup.callback(remove_file, "client_test.json")

        echo_server = start_echo_server()
        cleanup.callback(echo_server.close)

        server_proc = subprocess.Popen(["./build/socks", "-c", "server_test.json"], stdout=sys.stdout, stderr=sys.stderr)
        cleanup.callback(terminate_process, server_proc)
        time.sleep(1)  # Wait startup

        client_proc = subprocess.Popen(["./build/socks", "-c", "client_test.json"], stdout=sys.stdout, stderr=sys.stderr)
        cleanup.callback(terminate_process, client_proc)
        time.sleep(2)  # Wait connection

        success = socks5_handshake_and_echo()

    if success:
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
