#!/usr/bin/env python3

import argparse
import ipaddress
import socket
import struct
import sys


def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError("unexpected eof")
        data.extend(chunk)
    return bytes(data)


def parse_socks_address(sock):
    atyp = recv_exact(sock, 1)[0]
    if atyp == 0x01:
        host = socket.inet_ntoa(recv_exact(sock, 4))
    elif atyp == 0x04:
        host = socket.inet_ntop(socket.AF_INET6, recv_exact(sock, 16))
    elif atyp == 0x03:
        host_len = recv_exact(sock, 1)[0]
        host = recv_exact(sock, host_len).decode("utf-8")
    else:
        raise RuntimeError(f"unsupported atyp {atyp}")
    port = struct.unpack("!H", recv_exact(sock, 2))[0]
    return host, port


def encode_udp_header(host, port):
    addr = ipaddress.ip_address(host)
    header = bytearray(b"\x00\x00\x00")
    if addr.version == 4:
        header.append(0x01)
    else:
        header.append(0x04)
    header.extend(addr.packed)
    header.extend(struct.pack("!H", port))
    return bytes(header)


def decode_udp_packet(packet):
    if len(packet) < 10:
        raise RuntimeError("udp packet too short")
    if packet[0] != 0 or packet[1] != 0 or packet[2] != 0:
        raise RuntimeError("invalid socks udp header")
    atyp = packet[3]
    offset = 4
    if atyp == 0x01:
        host = socket.inet_ntoa(packet[offset : offset + 4])
        offset += 4
    elif atyp == 0x04:
        host = socket.inet_ntop(socket.AF_INET6, packet[offset : offset + 16])
        offset += 16
    elif atyp == 0x03:
        host_len = packet[offset]
        offset += 1
        host = packet[offset : offset + host_len].decode("utf-8")
        offset += host_len
    else:
        raise RuntimeError(f"unsupported atyp {atyp}")
    port = struct.unpack("!H", packet[offset : offset + 2])[0]
    offset += 2
    return host, port, packet[offset:]


def send_and_expect(udp_sock, relay, host, port, payload):
    udp_sock.sendto(encode_udp_header(host, port) + payload, relay)
    response, _peer = udp_sock.recvfrom(65535)
    source_host, source_port, response_payload = decode_udp_packet(response)
    if source_host != host or source_port != port:
        raise RuntimeError(f"unexpected source {source_host}:{source_port}, expected {host}:{port}")
    if response_payload != payload:
        raise RuntimeError(f"unexpected payload {response_payload!r}, expected {payload!r}")


def main():
    parser = argparse.ArgumentParser(description="Send multiple SOCKS5 UDP targets over one UDP associate")
    parser.add_argument("--socks-host", required=True)
    parser.add_argument("--socks-port", required=True, type=int)
    parser.add_argument("--target-a-host", required=True)
    parser.add_argument("--target-a-port", required=True, type=int)
    parser.add_argument("--target-b-host", required=True)
    parser.add_argument("--target-b-port", required=True, type=int)
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args()

    tcp_sock = socket.create_connection((args.socks_host, args.socks_port), timeout=args.timeout)
    tcp_sock.settimeout(args.timeout)
    try:
        tcp_sock.sendall(b"\x05\x01\x00")
        if recv_exact(tcp_sock, 2) != b"\x05\x00":
            raise RuntimeError("unexpected socks method reply")

        tcp_sock.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        version, rep, _rsv = recv_exact(tcp_sock, 3)
        if version != 0x05 or rep != 0x00:
            raise RuntimeError(f"udp associate failed version={version} rep={rep}")
        relay = parse_socks_address(tcp_sock)

        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.settimeout(args.timeout)
        try:
            send_and_expect(udp_sock, relay, args.target_a_host, args.target_a_port, b"socks-multi-a")
            send_and_expect(udp_sock, relay, args.target_b_host, args.target_b_port, b"socks-multi-b")
        finally:
            udp_sock.close()
    finally:
        tcp_sock.close()

    print("socks5 udp multi target ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
