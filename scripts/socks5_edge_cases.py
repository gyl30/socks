#!/usr/bin/env python3

import argparse
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


def recv_reply(sock):
    head = recv_exact(sock, 4)
    atyp = head[3]
    if atyp == 0x01:
        tail = recv_exact(sock, 6)
    elif atyp == 0x04:
        tail = recv_exact(sock, 18)
    elif atyp == 0x03:
        domain_len = recv_exact(sock, 1)[0]
        tail = bytes([domain_len]) + recv_exact(sock, domain_len + 2)
    else:
        raise RuntimeError(f"unsupported atyp {atyp}")
    return head + tail


def handshake_no_auth(sock):
    sock.sendall(b"\x05\x01\x00")
    reply = recv_exact(sock, 2)
    if reply != b"\x05\x00":
        raise RuntimeError(f"unexpected handshake reply {reply!r}")


def udp_associate(sock):
    request = b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00"
    sock.sendall(request)
    reply = recv_reply(sock)
    if reply[1] != 0x00:
        raise RuntimeError(f"udp associate failed rep={reply[1]}")
    atyp = reply[3]
    offset = 4
    if atyp == 0x01:
        relay_host = socket.inet_ntoa(reply[offset : offset + 4])
        offset += 4
    elif atyp == 0x04:
        relay_host = socket.inet_ntop(socket.AF_INET6, reply[offset : offset + 16])
        offset += 16
    else:
        raise RuntimeError(f"unsupported relay atyp {atyp}")
    relay_port = struct.unpack("!H", reply[offset : offset + 2])[0]
    return relay_host, relay_port


def encode_udp_packet(host, port, payload, frag=0, reserved=b"\x00\x00"):
    header = bytearray(reserved)
    header.append(frag)
    try:
        socket.inet_aton(host)
        header.append(0x01)
        header.extend(socket.inet_aton(host))
    except OSError as exc:
        raise RuntimeError(f"only ipv4 host is supported in edge tests: {exc}") from exc
    header.extend(struct.pack("!H", port))
    header.extend(payload)
    return bytes(header)


def expect_no_acceptable_method(host, port, timeout):
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        sock.sendall(b"\x05\x01\x01")
        reply = recv_exact(sock, 2)
        if reply != b"\x05\xff":
            raise RuntimeError(f"unexpected no acceptable method reply {reply!r}")
    finally:
        sock.close()


def expect_cmd_not_supported(host, port, timeout):
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        handshake_no_auth(sock)
        request = b"\x05\x02\x00\x01\x7f\x00\x00\x01\x00\x50"
        sock.sendall(request)
        reply = recv_reply(sock)
        if reply[1] != 0x07:
            raise RuntimeError(f"unexpected bind reply rep={reply[1]}")
    finally:
        sock.close()


def expect_addr_type_not_supported(host, port, timeout):
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        handshake_no_auth(sock)
        request = b"\x05\x01\x00\x05\x00\x50"
        sock.sendall(request)
        reply = recv_reply(sock)
        if reply[1] != 0x08:
            raise RuntimeError(f"unexpected atyp reply rep={reply[1]}")
    finally:
        sock.close()


def expect_connect_port_zero_rejected(host, port, timeout):
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        handshake_no_auth(sock)
        request = b"\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x00"
        sock.sendall(request)
        reply = recv_reply(sock)
        if reply[1] != 0x01:
            raise RuntimeError(f"unexpected port zero reply rep={reply[1]}")
    finally:
        sock.close()


def expect_udp_packet_ignored(host, port, timeout, payload, frag=0, target_port=1, reserved=b"\x00\x00"):
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.settimeout(timeout)
    try:
        handshake_no_auth(sock)
        relay_host, relay_port = udp_associate(sock)
        packet = encode_udp_packet("127.0.0.1", target_port, payload, frag=frag, reserved=reserved)
        udp_sock.sendto(packet, (relay_host, relay_port))
        try:
            udp_sock.recvfrom(65535)
        except socket.timeout:
            return
        raise RuntimeError("unexpected udp response for ignored packet")
    finally:
        udp_sock.close()
        sock.close()


def main():
    parser = argparse.ArgumentParser(description="SOCKS5 edge case checks")
    parser.add_argument("--socks-host", required=True)
    parser.add_argument("--socks-port", required=True, type=int)
    parser.add_argument("--timeout", type=float, default=1.5)
    args = parser.parse_args()

    expect_no_acceptable_method(args.socks_host, args.socks_port, args.timeout)
    print("socks5 no acceptable method ok")

    expect_cmd_not_supported(args.socks_host, args.socks_port, args.timeout)
    print("socks5 unsupported command ok")

    expect_addr_type_not_supported(args.socks_host, args.socks_port, args.timeout)
    print("socks5 unsupported atyp ok")

    expect_connect_port_zero_rejected(args.socks_host, args.socks_port, args.timeout)
    print("socks5 connect port zero rejected ok")

    expect_udp_packet_ignored(args.socks_host, args.socks_port, args.timeout, b"frag", frag=1)
    print("socks5 udp fragmented packet ignored ok")

    expect_udp_packet_ignored(args.socks_host, args.socks_port, args.timeout, b"port-zero", target_port=0)
    print("socks5 udp port zero ignored ok")

    expect_udp_packet_ignored(args.socks_host, args.socks_port, args.timeout, b"reserved", reserved=b"\x00\x01")
    print("socks5 udp invalid reserved ignored ok")

    return 0


if __name__ == "__main__":
    sys.exit(main())
