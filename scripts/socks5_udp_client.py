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
    elif atyp == 0x03:
        host_len = recv_exact(sock, 1)[0]
        host = recv_exact(sock, host_len).decode("utf-8")
    elif atyp == 0x04:
        host = socket.inet_ntop(socket.AF_INET6, recv_exact(sock, 16))
    else:
        raise RuntimeError(f"unsupported atyp {atyp}")
    port = struct.unpack("!H", recv_exact(sock, 2))[0]
    return host, port


def encode_udp_header(host, port):
    try:
        addr = ipaddress.ip_address(host)
    except ValueError as exc:
        raise RuntimeError(f"only ip target is supported in this test helper: {exc}") from exc

    header = bytearray(b"\x00\x00\x00")
    if addr.version == 4:
        header.append(0x01)
        header.extend(addr.packed)
    else:
        header.append(0x04)
        header.extend(addr.packed)
    header.extend(struct.pack("!H", port))
    return bytes(header)


def decode_udp_packet(packet):
    if len(packet) < 10:
        raise RuntimeError("udp packet too short")
    if packet[0] != 0 or packet[1] != 0:
        raise RuntimeError("invalid reserved field")
    frag = packet[2]
    if frag != 0:
        raise RuntimeError(f"unexpected frag {frag}")
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


def main():
    parser = argparse.ArgumentParser(description="Minimal SOCKS5 UDP associate client for integration tests")
    parser.add_argument("--socks-host", required=True)
    parser.add_argument("--socks-port", required=True, type=int)
    parser.add_argument("--target-host", required=True)
    parser.add_argument("--target-port", required=True, type=int)
    parser.add_argument("--payload", required=True)
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args()

    tcp_sock = socket.create_connection((args.socks_host, args.socks_port), timeout=args.timeout)
    tcp_sock.settimeout(args.timeout)
    try:
        tcp_sock.sendall(b"\x05\x01\x00")
        method_reply = recv_exact(tcp_sock, 2)
        if method_reply != b"\x05\x00":
            raise RuntimeError(f"unexpected method reply {method_reply!r}")

        associate_request = b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00"
        tcp_sock.sendall(associate_request)

        version, rep, _rsv = recv_exact(tcp_sock, 3)
        if version != 0x05 or rep != 0x00:
            raise RuntimeError(f"udp associate failed version={version} rep={rep}")
        relay_host, relay_port = parse_socks_address(tcp_sock)

        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.settimeout(args.timeout)
        try:
            request = encode_udp_header(args.target_host, args.target_port) + args.payload.encode("utf-8")
            udp_sock.sendto(request, (relay_host, relay_port))
            response, _peer = udp_sock.recvfrom(65535)
        finally:
            udp_sock.close()

        source_host, source_port, payload = decode_udp_packet(response)
        if source_host != args.target_host or source_port != args.target_port:
            raise RuntimeError(
                f"unexpected udp source {source_host}:{source_port} expected {args.target_host}:{args.target_port}"
            )
        payload_text = payload.decode("utf-8")
        if payload_text != args.payload:
            raise RuntimeError(f"unexpected udp payload {payload_text!r}")
        print(payload_text)
    finally:
        tcp_sock.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
