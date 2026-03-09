#!/usr/bin/env python3

import argparse
import socket
import sys
import time


def build_request(host, path):
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: tproxy-test-client/1.0\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")


def fetch_response(sock, args):
    response = bytearray()
    while True:
        try:
            chunk = sock.recv(65536)
        except socket.timeout as exc:
            raise RuntimeError("read timeout") from exc
        if not chunk:
            break
        response.extend(chunk)
        if len(response) > args.max_bytes:
            raise RuntimeError(f"response too large {len(response)}")
    if b"\r\n\r\n" not in response:
        raise RuntimeError("missing http header")

    header_bytes, body = response.split(b"\r\n\r\n", 1)
    header_text = header_bytes.decode("iso-8859-1")
    status_line = header_text.split("\r\n", 1)[0]
    parts = status_line.split()
    if len(parts) < 2:
        raise RuntimeError(f"invalid status line {status_line!r}")
    status_code = int(parts[1])
    if status_code != args.expect_status:
        raise RuntimeError(f"unexpected status {status_code}")

    if args.expect_substring:
        expected = args.expect_substring.encode("utf-8")
        if expected not in body:
            raise RuntimeError("expected substring not found")

    print(f"tcp fetch ok status={status_code} bytes={len(response)} body_bytes={len(body)}")


def hold_without_reading(sock, args):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, args.recv_buffer)
    deadline = time.time() + args.hold_seconds
    while time.time() < deadline:
        time.sleep(0.1)
    print(f"tcp hold ok seconds={args.hold_seconds}")


def main():
    parser = argparse.ArgumentParser(description="Minimal TCP HTTP client for TPROXY tests")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--path", default="/")
    parser.add_argument("--mode", choices=("fetch", "hold-no-read"), default="fetch")
    parser.add_argument("--connect-timeout", type=float, default=3.0)
    parser.add_argument("--read-timeout", type=float, default=10.0)
    parser.add_argument("--hold-seconds", type=float, default=5.0)
    parser.add_argument("--recv-buffer", type=int, default=4096)
    parser.add_argument("--max-bytes", type=int, default=134217728)
    parser.add_argument("--expect-status", type=int, default=200)
    parser.add_argument("--expect-substring", default="")
    args = parser.parse_args()

    try:
        sock = socket.create_connection((args.host, args.port), timeout=args.connect_timeout)
    except OSError as exc:
        print(f"tcp connect failed {exc}", file=sys.stderr)
        return 1

    try:
        sock.settimeout(args.read_timeout)
        sock.sendall(build_request(args.host, args.path))
        if args.mode == "fetch":
            fetch_response(sock, args)
        else:
            hold_without_reading(sock, args)
    except Exception as exc:
        print(f"tcp client failed {exc}", file=sys.stderr)
        return 1
    finally:
        try:
            sock.close()
        except OSError:
            pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
