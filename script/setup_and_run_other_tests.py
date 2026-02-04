import subprocess
import json
import time
import os
import signal
import sys

BUILD_DIR = "./build"
SOCKS_BIN = "./socks"

def generate_keys():
    try:
        output = subprocess.check_output([SOCKS_BIN, "x25519"], cwd=BUILD_DIR).decode()
        lines = output.strip().split('\n')
        sk = lines[0].split(': ')[1].strip()
        pk = lines[1].split(': ')[1].strip()
        vk = lines[2].split(': ')[1].strip()
        return sk, pk, vk
    except Exception as e:
        print(f"Key gen failed: {e}")
        sys.exit(1)

def generate_cert(sni):
    cert_file = f"{BUILD_DIR}/{sni}.crt"
    key_file = f"{BUILD_DIR}/{sni}.key"
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", key_file, "-out", cert_file,
        "-days", "365", "-nodes", "-subj", f"/CN={sni}"
    ]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return cert_file, key_file

def start_fake_tls_server(port, sni):
    cert, key = generate_cert(sni)
    cmd = [
        "openssl", "s_server",
        "-accept", str(port),
        "-cert", cert,
        "-key", key,
        "-tls1_3",
        "-quiet",
        "-www"
    ]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def main():
    sk, pk, vk = generate_keys()
    short_id = "0123456789abcdef"
    sni = "www.example.com"
    fallback_port = 14443

    # Start Fake TLS Server
    tls_server = start_fake_tls_server(fallback_port, sni)
    print(f"[*] Fake TLS Server started on {fallback_port}")

    # Server Config
    server_cfg = {
        "mode": "server",
        "log": {"level": "info", "file": "manual_server.log"},
        "inbound": {"host": "127.0.0.1", "port": 20000},
        "reality": {
            "sni": sni,
            "private_key": sk,
            "public_key": pk,
            "short_id": short_id
        },
        "fallbacks": [{"sni": sni, "host": "127.0.0.1", "port": str(fallback_port)}],
    }

    # Client Config
    client_cfg = {
        "mode": "client",
        "log": {"level": "info", "file": "manual_client.log"},
        "inbound": {"host": "127.0.0.1", "port": 1080},
        "outbound": {"host": "127.0.0.1", "port": 20000},
        "socks": {"host": "127.0.0.1", "port": 1080, "auth": False},
        "reality": {
            "sni": sni,
            "public_key": pk,
            "private_key": sk,
            "short_id": short_id,
            "verify_public_key": vk
        }
    }

    with open(f"{BUILD_DIR}/manual_server.json", "w") as f:
        json.dump(server_cfg, f, indent=4)
    
    with open(f"{BUILD_DIR}/manual_client.json", "w") as f:
        json.dump(client_cfg, f, indent=4)

    print("[*] Starting Server...")
    sp = subprocess.Popen([SOCKS_BIN, "-c", "manual_server.json"], cwd=BUILD_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    print("[*] Starting Client...")
    cp = subprocess.Popen([SOCKS_BIN, "-c", "manual_client.json"], cwd=BUILD_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    time.sleep(2) # Wait for startup

    try:
        print("\n>>> Running Parallel Test <<<")
        subprocess.run(["python3", "script/parallel_test.py"], check=False)

        print("\n>>> Running UDP Test <<<")
        subprocess.run(["python3", "script/test_udp.py"], check=False)

    finally:
        print("\n[*] Stopping processes...")
        os.kill(sp.pid, signal.SIGTERM)
        os.kill(cp.pid, signal.SIGTERM)
        tls_server.terminate()
        sp.wait()
        cp.wait()
        tls_server.wait()

if __name__ == "__main__":
    main()
