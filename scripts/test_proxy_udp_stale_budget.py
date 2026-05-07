#!/usr/bin/env python3

import argparse
import pathlib
import shutil
import socket
import sys
import tempfile
import threading
import time

from testlib import (
    allocate_tcp_port,
    build_runtime_env,
    make_reality_client_config,
    make_reality_server_config,
    parse_key_output,
    run_checked,
    save_json,
    start_process,
    tail_file,
    wait_for_log_text,
    wait_for_port,
)


def read_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError("socket closed before expected bytes")
        data.extend(chunk)
    return bytes(data)


def read_socks5_reply(sock):
    reply = read_exact(sock, 4)
    atyp = reply[3]
    if atyp == 1:
        bind_host = socket.inet_ntoa(read_exact(sock, 4))
    elif atyp == 3:
        bind_host = read_exact(sock, read_exact(sock, 1)[0]).decode("ascii")
    elif atyp == 4:
        bind_host = socket.inet_ntop(socket.AF_INET6, read_exact(sock, 16))
    else:
        raise RuntimeError(f"unexpected socks5 reply atyp={atyp}")
    bind_port = int.from_bytes(read_exact(sock, 2), "big")
    return reply[1], bind_host, bind_port


def open_socks5_udp_associate(socks_port):
    tcp_sock = socket.create_connection(("127.0.0.1", socks_port), timeout=5)
    tcp_sock.settimeout(10)
    tcp_sock.sendall(b"\x05\x01\x00")
    if read_exact(tcp_sock, 2) != b"\x05\x00":
        tcp_sock.close()
        raise RuntimeError("socks5 auth negotiation failed")

    tcp_sock.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    reply_rep, bind_host, bind_port = read_socks5_reply(tcp_sock)
    if reply_rep != 0:
        tcp_sock.close()
        raise RuntimeError(f"socks5 udp associate failed rep={reply_rep}")
    return tcp_sock, bind_host, bind_port


def open_udp_peer_socket():
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(("127.0.0.1", 0))
    udp_sock.settimeout(1)
    return udp_sock


def send_socks5_udp_datagram(udp_sock, bind_host, bind_port, target_host, target_port, payload):
    packet = b"\x00\x00\x00\x01" + socket.inet_aton(target_host) + target_port.to_bytes(2, "big") + payload
    udp_sock.sendto(packet, (bind_host, bind_port))


class DelayedSocksServer:
    def __init__(self, delay_seconds):
        self.delay_seconds = delay_seconds
        self.accepted_connections = 0
        self._ready = threading.Event()
        self._stop = threading.Event()
        self._errors = []
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(1)
        self._listener.settimeout(0.2)
        self.port = self._listener.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        if not self._ready.wait(5):
            raise RuntimeError("delayed socks server did not start")

    def _serve(self):
        try:
            self._ready.set()
            while not self._stop.is_set():
                try:
                    conn, _addr = self._listener.accept()
                except TimeoutError:
                    continue
                except OSError:
                    if self._stop.is_set():
                        break
                    raise
                self.accepted_connections += 1
                with conn:
                    conn.settimeout(10)
                    method_request = read_exact(conn, 3)
                    if method_request != b"\x05\x01\x00":
                        raise RuntimeError(f"unexpected method request {method_request!r}")
                    conn.sendall(b"\x05\x00")

                    request = read_exact(conn, 4)
                    if request[0] != 0x05 or request[2] != 0x00 or request[1] not in (0x01, 0x03):
                        raise RuntimeError(f"unexpected socks request head {request!r}")
                    atyp = request[3]
                    if atyp == 1:
                        read_exact(conn, 4)
                    elif atyp == 3:
                        read_exact(conn, read_exact(conn, 1)[0])
                    elif atyp == 4:
                        read_exact(conn, 16)
                    else:
                        raise RuntimeError(f"unexpected atyp {atyp}")
                    read_exact(conn, 2)

                    time.sleep(self.delay_seconds)
                    conn.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
                    break
        except Exception as exc:
            self._errors.append(str(exc))
        finally:
            self._listener.close()

    def close(self):
        self._stop.set()
        self._listener.close()
        self._thread.join(timeout=self.delay_seconds + 5)
        if self._thread.is_alive():
            raise RuntimeError("delayed socks server did not exit")
        if self._errors:
            raise RuntimeError(self._errors[0])


def build_reality_keypair(binary, runtime_env):
    result = run_checked([str(binary), "x25519"], env=runtime_env, capture_output=True)
    return parse_key_output(result.stdout)


def fail_with_logs(message, *paths):
    tails = "\n".join(f"===== {path.name} =====\n{tail_file(path)}" for path in paths)
    raise RuntimeError(f"{message}\n{tails}")


def main():
    parser = argparse.ArgumentParser(description="Verify delayed UDP proxy outbound open reuses remaining session budget")
    parser.add_argument("--binary", required=True)
    args = parser.parse_args()

    binary = pathlib.Path(args.binary).resolve()
    runtime_env = build_runtime_env(binary)
    temp_root = pathlib.Path(tempfile.mkdtemp(prefix="proxy-udp-stale-budget-"))
    processes = []
    delayed_socks = None
    fast_socks = None
    udp_peer_sock = None
    udp_tcp_sock = None

    try:
        fast_socks = DelayedSocksServer(delay_seconds=0.0)
        delayed_socks = DelayedSocksServer(delay_seconds=4.0)

        client_socks_port = allocate_tcp_port()
        reality_a_port = allocate_tcp_port()
        reality_b_port = allocate_tcp_port()
        short_id = "0102030405060708"
        sni = "www.apple.com"

        a_private_key, a_public_key = build_reality_keypair(binary, runtime_env)
        b_private_key, b_public_key = build_reality_keypair(binary, runtime_env)

        client_log = temp_root / "client.log"
        server_a_log = temp_root / "server-a.log"
        server_b_log = temp_root / "server-b.log"

        server_b_cfg = make_reality_server_config(
            log_file=server_b_log,
            port=reality_b_port,
            sni=sni,
            private_key=b_private_key,
            public_key=b_public_key,
            short_id=short_id,
            outbounds=[
                {
                    "type": "socks",
                    "tag": "socks-fast",
                    "settings": {
                        "host": "127.0.0.1",
                        "port": fast_socks.port,
                        "auth": False,
                    },
                },
                {
                    "type": "socks",
                    "tag": "socks-delayed",
                    "settings": {
                        "host": "127.0.0.1",
                        "port": delayed_socks.port,
                        "auth": False,
                    },
                }
            ],
            routing=[
                {
                    "type": "ip",
                    "values": ["127.0.0.1/32"],
                    "out": "socks-fast",
                },
                {
                    "type": "ip",
                    "values": ["127.0.0.2/32"],
                    "out": "socks-delayed",
                }
            ],
        )
        server_b_cfg["timeout"].update({"read": 5, "write": 5, "connect": 5, "idle": 5})

        server_a_cfg = make_reality_server_config(
            log_file=server_a_log,
            port=reality_a_port,
            sni=sni,
            private_key=a_private_key,
            public_key=a_public_key,
            short_id=short_id,
            outbounds=[
                {
                    "type": "reality",
                    "tag": "reality-out-b",
                    "settings": {
                        "host": "127.0.0.1",
                        "port": reality_b_port,
                        "sni": sni,
                        "fingerprint": "random",
                        "public_key": b_public_key,
                        "short_id": short_id,
                        "max_handshake_records": 256,
                    },
                }
            ],
            routing=[
                {
                    "type": "inbound",
                    "values": ["reality-in"],
                    "out": "reality-out-b",
                }
            ],
        )
        server_a_cfg["timeout"].update({"read": 5, "write": 5, "connect": 5, "idle": 5})

        client_cfg = make_reality_client_config(
            log_file=client_log,
            socks_port=client_socks_port,
            server_port=reality_a_port,
            sni=sni,
            public_key=a_public_key,
            short_id=short_id,
        )
        client_cfg["timeout"].update({"read": 1, "write": 1, "connect": 1, "idle": 5})

        save_json(temp_root / "server-b.json", server_b_cfg)
        save_json(temp_root / "server-a.json", server_a_cfg)
        save_json(temp_root / "client.json", client_cfg)

        server_b = start_process([str(binary), "-c", str(temp_root / "server-b.json")], str(temp_root / "server-b.stdout.log"), extra_env=runtime_env)
        processes.append(server_b)
        wait_for_log_text(server_b_log, f"listen 127.0.0.1:{reality_b_port} reality inbound listening", 20, "server b ready", processes)

        server_a = start_process([str(binary), "-c", str(temp_root / "server-a.json")], str(temp_root / "server-a.stdout.log"), extra_env=runtime_env)
        processes.append(server_a)
        wait_for_log_text(server_a_log, f"listen 127.0.0.1:{reality_a_port} reality inbound listening", 20, "server a ready", processes)

        client = start_process([str(binary), "-c", str(temp_root / "client.json")], str(temp_root / "client.stdout.log"), extra_env=runtime_env)
        processes.append(client)
        wait_for_port("127.0.0.1", client_socks_port, 20, "client socks", processes)

        udp_tcp_sock, udp_bind_host, udp_bind_port = open_socks5_udp_associate(client_socks_port)
        udp_peer_sock = open_udp_peer_socket()
        send_socks5_udp_datagram(udp_peer_sock, udp_bind_host, udp_bind_port, "127.0.0.1", 80, b"fast-open")
        try:
            wait_for_log_text(
                server_b_log,
                "out_tag socks-fast open proxy udp outbound failed",
                6,
                "server b fast udp outbound failure",
                processes,
            )
        except RuntimeError as exc:
            fail_with_logs(str(exc), client_log, server_a_log, server_b_log)
        if fast_socks.accepted_connections != 1:
            fail_with_logs(
                f"fast udp outbound did not reach expected upstream accepted={fast_socks.accepted_connections}",
                client_log,
                server_a_log,
                server_b_log,
            )

        time.sleep(3.0)

        udp_elapsed_start = time.monotonic()
        send_socks5_udp_datagram(udp_peer_sock, udp_bind_host, udp_bind_port, "127.0.0.2", 80, b"stale-budget")
        try:
            wait_for_log_text(
                server_b_log,
                "out_tag socks-delayed open proxy udp outbound failed",
                6,
                "server b stale udp budget failure",
                processes,
            )
        except RuntimeError as exc:
            fail_with_logs(str(exc), client_log, server_a_log, server_b_log)
        udp_elapsed_seconds = time.monotonic() - udp_elapsed_start

        time.sleep(0.5)
        if delayed_socks.accepted_connections != 0:
            fail_with_logs(
                f"delayed udp unexpectedly reached upstream accepted={delayed_socks.accepted_connections}",
                client_log,
                server_a_log,
                server_b_log,
            )

        print(f"proxy udp stale budget ok elapsed={udp_elapsed_seconds:.2f}s")
    finally:
        for process in reversed(processes):
            process.terminate()
        if udp_peer_sock is not None:
            udp_peer_sock.close()
        if udp_tcp_sock is not None:
            udp_tcp_sock.close()
        if fast_socks is not None:
            fast_socks.close()
        if delayed_socks is not None:
            delayed_socks.close()
        shutil.rmtree(temp_root, ignore_errors=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"test failed {exc}", file=sys.stderr)
        sys.exit(1)
