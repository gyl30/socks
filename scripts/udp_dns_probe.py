#!/usr/bin/env python3

import random
import secrets
import socket
import struct
import sys


def encode_qname(name: str) -> bytes:
    labels = [label for label in name.rstrip(".").split(".") if label]
    if not labels:
        raise ValueError("empty dns name")
    encoded = bytearray()
    for label in labels:
        data = label.encode("idna")
        if len(data) > 63:
            raise ValueError("dns label too long")
        encoded.append(len(data))
        encoded.extend(data)
    encoded.append(0)
    return bytes(encoded)


def build_query(name: str, txid: int) -> bytes:
    flags = 0x0100  # recursion desired
    header = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0)
    question = encode_qname(name) + struct.pack("!HH", 1, 1)
    return header + question


def main() -> int:
    if len(sys.argv) != 5:
        print("usage: udp_dns_probe.py <host> <port> <name> <timeout_sec>", file=sys.stderr)
        return 2

    host = sys.argv[1]
    port = int(sys.argv[2])
    name = sys.argv[3]
    timeout = float(sys.argv[4])
    txid = secrets.randbelow(0x10000)
    payload = build_query(name, txid)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(payload, (host, port))
        data, _ = sock.recvfrom(4096)

    if len(data) < 12:
        print("short dns reply", file=sys.stderr)
        return 1

    reply_txid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    if reply_txid != txid:
        print(f"transaction id mismatch: expected {txid} got {reply_txid}", file=sys.stderr)
        return 1

    if (flags & 0x8000) == 0:
        print("not a response", file=sys.stderr)
        return 1

    rcode = flags & 0x000F
    if rcode != 0:
        print(f"dns rcode {rcode}", file=sys.stderr)
        return 1

    if qdcount != 1:
        print(f"unexpected qdcount {qdcount}", file=sys.stderr)
        return 1

    if ancount == 0 and nscount == 0 and arcount == 0:
        print("empty dns response", file=sys.stderr)
        return 1

    print(f"ok host={host} port={port} name={name} an={ancount} ns={nscount} ar={arcount}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
