#!/usr/bin/env python3

import argparse
import signal
import socket
import sys


running = True


def handle_signal(_signum, _frame):
    global running
    running = False


def main():
    parser = argparse.ArgumentParser(description="Simple UDP echo server for SOCKS5 tests")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    args = parser.parse_args()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.host, args.port))
    sock.settimeout(0.5)

    try:
        while running:
            try:
                data, peer = sock.recvfrom(65535)
            except socket.timeout:
                continue
            sock.sendto(data, peer)
    finally:
        sock.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
