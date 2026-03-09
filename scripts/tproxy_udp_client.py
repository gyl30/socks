#!/usr/bin/env python3

import argparse
import socket
import sys
import time


def build_payload(args):
    if args.payload:
        return args.payload.encode("utf-8")
    return (args.fill_char * args.payload_size).encode("ascii")


def main():
    parser = argparse.ArgumentParser(description="Minimal UDP client for TPROXY tests")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--bind-host", default="0.0.0.0")
    parser.add_argument("--payload", default="")
    parser.add_argument("--payload-size", type=int, default=32)
    parser.add_argument("--fill-char", default="u")
    parser.add_argument("--timeout", type=float, default=1.5)
    parser.add_argument("--expect-echo", action="store_true")
    parser.add_argument("--expect-timeout", action="store_true")
    parser.add_argument("--pause-ms", type=int, default=0)
    args = parser.parse_args()

    if len(args.fill_char) != 1:
        print("fill-char must be a single character", file=sys.stderr)
        return 1
    if args.expect_echo and args.expect_timeout:
        print("expect-echo and expect-timeout cannot both be set", file=sys.stderr)
        return 1

    payload = build_payload(args)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout)

    try:
        sock.bind((args.bind_host, 0))
        sock.sendto(payload, (args.host, args.port))
        if args.pause_ms > 0:
            time.sleep(args.pause_ms / 1000.0)

        try:
            response, peer = sock.recvfrom(65535)
        except socket.timeout:
            if args.expect_timeout:
                print(f"udp timeout ok bytes={len(payload)}")
                return 0
            print("udp receive timeout", file=sys.stderr)
            return 1

        if args.expect_timeout:
            print(f"unexpected udp response from {peer[0]}:{peer[1]}", file=sys.stderr)
            return 1
        if args.expect_echo and response != payload:
            print("udp echo mismatch", file=sys.stderr)
            return 1
        print(f"udp ok bytes={len(response)} peer={peer[0]}:{peer[1]}")
        return 0
    finally:
        sock.close()


if __name__ == "__main__":
    raise SystemExit(main())
