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


def parse_reply_address(reply):
    atyp = reply[3]
    offset = 4
    if atyp == 0x01:
        host = socket.inet_ntoa(reply[offset : offset + 4])
        offset += 4
    elif atyp == 0x04:
        host = socket.inet_ntop(socket.AF_INET6, reply[offset : offset + 16])
        offset += 16
    elif atyp == 0x03:
        host_len = reply[offset]
        offset += 1
        host = reply[offset : offset + host_len].decode("utf-8")
        offset += host_len
    else:
        raise RuntimeError(f"unsupported reply atyp {atyp}")
    port = struct.unpack("!H", reply[offset : offset + 2])[0]
    return host, port


def handshake_no_auth(sock):
    sock.sendall(b"\x05\x01\x00")
    reply = recv_exact(sock, 2)
    if reply != b"\x05\x00":
        raise RuntimeError(f"unexpected handshake reply {reply!r}")


def encode_request_address(host, force_domain=False):
    if force_domain:
        encoded_host = host.encode("utf-8")
        if not encoded_host or len(encoded_host) > 255:
            raise RuntimeError(f"invalid domain host {host!r}")
        return bytes([0x03, len(encoded_host)]) + encoded_host

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        encoded_host = host.encode("utf-8")
        if not encoded_host or len(encoded_host) > 255:
            raise RuntimeError(f"invalid host {host!r}")
        return bytes([0x03, len(encoded_host)]) + encoded_host

    if address.version == 4:
        return b"\x01" + address.packed
    return b"\x04" + address.packed


def udp_associate(sock, request_host="0.0.0.0", request_port=0, force_domain=False):
    request = bytearray(b"\x05\x03\x00")
    request.extend(encode_request_address(request_host, force_domain=force_domain))
    request.extend(struct.pack("!H", request_port))
    sock.sendall(request)
    reply = recv_reply(sock)
    return reply


def create_associated_session(socks_host, socks_port, timeout, request_host="0.0.0.0", request_port=0, force_domain=False):
    tcp_sock = socket.create_connection((socks_host, socks_port), timeout=timeout)
    tcp_sock.settimeout(timeout)
    handshake_no_auth(tcp_sock)
    reply = udp_associate(tcp_sock, request_host=request_host, request_port=request_port, force_domain=force_domain)
    if reply[1] != 0x00:
        raise RuntimeError(f"udp associate failed rep={reply[1]}")
    relay_host, relay_port = parse_reply_address(reply)
    return tcp_sock, relay_host, relay_port


def bind_udp_socket(timeout):
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(("127.0.0.1", 0))
    udp_sock.settimeout(timeout)
    return udp_sock


def encode_udp_packet(host, port, payload, force_domain=False):
    header = bytearray(b"\x00\x00\x00")
    header.extend(encode_request_address(host, force_domain=force_domain))
    header.extend(struct.pack("!H", port))
    header.extend(payload)
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


def send_and_expect_timeout(udp_sock, relay_host, relay_port, packet):
    udp_sock.sendto(packet, (relay_host, relay_port))
    try:
        udp_sock.recvfrom(65535)
    except socket.timeout:
        return
    raise RuntimeError("unexpected udp response for ignored packet")


def send_and_expect_echo(udp_sock, relay_host, relay_port, packet, expected_host, expected_port, expected_payload):
    udp_sock.sendto(packet, (relay_host, relay_port))
    response, _peer = udp_sock.recvfrom(65535)
    source_host, source_port, payload = decode_udp_packet(response)
    if source_host != expected_host or source_port != expected_port:
        raise RuntimeError(f"unexpected udp source {source_host}:{source_port} expected {expected_host}:{expected_port}")
    if payload != expected_payload:
        raise RuntimeError(f"unexpected udp payload {payload!r}")


def expect_udp_associate_host_mismatch_allowed(host, port, timeout, target_port):
    tcp_sock = socket.create_connection((host, port), timeout=timeout)
    tcp_sock.settimeout(timeout)
    try:
        handshake_no_auth(tcp_sock)
        reply = udp_associate(tcp_sock, request_host="127.0.0.2", request_port=0)
        if reply[1] != 0x00:
            raise RuntimeError(f"unexpected udp associate reply rep={reply[1]}")
        relay_host, relay_port = parse_reply_address(reply)
        udp_sock = bind_udp_socket(timeout)
        try:
            packet = encode_udp_packet("127.0.0.1", target_port, b"udp-associate-mismatch-allowed")
            send_and_expect_echo(udp_sock, relay_host, relay_port, packet, "127.0.0.1", target_port, b"udp-associate-mismatch-allowed")
        finally:
            udp_sock.close()
    finally:
        tcp_sock.close()


def expect_udp_associate_domain_allowed(host, port, timeout, target_port):
    tcp_sock, relay_host, relay_port = create_associated_session(
        host,
        port,
        timeout,
        request_host="client.invalid",
        request_port=0,
        force_domain=True,
    )
    udp_sock = bind_udp_socket(timeout)
    try:
        packet = encode_udp_packet("127.0.0.1", target_port, b"udp-associate-domain-echo")
        send_and_expect_echo(udp_sock, relay_host, relay_port, packet, "127.0.0.1", target_port, b"udp-associate-domain-echo")
    finally:
        udp_sock.close()
        tcp_sock.close()


def expect_udp_domain_encoded_target_ok(host, port, timeout, target_port):
    tcp_sock, relay_host, relay_port = create_associated_session(host, port, timeout)
    udp_sock = bind_udp_socket(timeout)
    try:
        packet = encode_udp_packet("127.0.0.1", target_port, b"udp-domain", force_domain=True)
        send_and_expect_echo(udp_sock, relay_host, relay_port, packet, "127.0.0.1", target_port, b"udp-domain")
    finally:
        udp_sock.close()
        tcp_sock.close()


def expect_udp_short_packet_ignored_then_recover(host, port, timeout, target_port):
    tcp_sock, relay_host, relay_port = create_associated_session(host, port, timeout)
    udp_sock = bind_udp_socket(timeout)
    try:
        send_and_expect_timeout(udp_sock, relay_host, relay_port, b"\x00\x00\x00")
        packet = encode_udp_packet("127.0.0.1", target_port, b"udp-short-ok")
        send_and_expect_echo(udp_sock, relay_host, relay_port, packet, "127.0.0.1", target_port, b"udp-short-ok")
    finally:
        udp_sock.close()
        tcp_sock.close()


def expect_udp_invalid_atyp_ignored_then_recover(host, port, timeout, target_port):
    tcp_sock, relay_host, relay_port = create_associated_session(host, port, timeout)
    udp_sock = bind_udp_socket(timeout)
    try:
        invalid_packet = b"\x00\x00\x00\x05\x00\x50bad"
        send_and_expect_timeout(udp_sock, relay_host, relay_port, invalid_packet)
        packet = encode_udp_packet("127.0.0.1", target_port, b"udp-atyp-ok")
        send_and_expect_echo(udp_sock, relay_host, relay_port, packet, "127.0.0.1", target_port, b"udp-atyp-ok")
    finally:
        udp_sock.close()
        tcp_sock.close()


def expect_udp_zero_domain_len_ignored_then_recover(host, port, timeout, target_port):
    tcp_sock, relay_host, relay_port = create_associated_session(host, port, timeout)
    udp_sock = bind_udp_socket(timeout)
    try:
        invalid_packet = b"\x00\x00\x00\x03\x00\x00\x50bad"
        send_and_expect_timeout(udp_sock, relay_host, relay_port, invalid_packet)
        packet = encode_udp_packet("127.0.0.1", target_port, b"udp-zero-domain-ok")
        send_and_expect_echo(udp_sock, relay_host, relay_port, packet, "127.0.0.1", target_port, b"udp-zero-domain-ok")
    finally:
        udp_sock.close()
        tcp_sock.close()


def expect_udp_request_port_constraint(host, port, timeout, target_port):
    good_sock = bind_udp_socket(timeout)
    bad_sock = bind_udp_socket(timeout)
    tcp_sock, relay_host, relay_port = create_associated_session(
        host,
        port,
        timeout,
        request_host="0.0.0.0",
        request_port=good_sock.getsockname()[1],
    )
    try:
        bad_packet = encode_udp_packet("127.0.0.1", target_port, b"udp-bad-port")
        send_and_expect_echo(bad_sock, relay_host, relay_port, bad_packet, "127.0.0.1", target_port, b"udp-bad-port")

        good_packet = encode_udp_packet("127.0.0.1", target_port, b"udp-good-port")
        send_and_expect_timeout(good_sock, relay_host, relay_port, good_packet)
    finally:
        tcp_sock.close()
        bad_sock.close()
        good_sock.close()


def expect_udp_bound_peer_rebind_ignored(host, port, timeout, target_port):
    tcp_sock, relay_host, relay_port = create_associated_session(host, port, timeout)
    first_sock = bind_udp_socket(timeout)
    second_sock = bind_udp_socket(timeout)
    try:
        first_packet = encode_udp_packet("127.0.0.1", target_port, b"udp-bind-first")
        send_and_expect_echo(first_sock, relay_host, relay_port, first_packet, "127.0.0.1", target_port, b"udp-bind-first")

        second_packet = encode_udp_packet("127.0.0.1", target_port, b"udp-bind-second")
        send_and_expect_timeout(second_sock, relay_host, relay_port, second_packet)

        third_packet = encode_udp_packet("127.0.0.1", target_port, b"udp-bind-third")
        send_and_expect_echo(first_sock, relay_host, relay_port, third_packet, "127.0.0.1", target_port, b"udp-bind-third")
    finally:
        second_sock.close()
        first_sock.close()
        tcp_sock.close()


def main():
    parser = argparse.ArgumentParser(description="SOCKS5 UDP edge case checks")
    parser.add_argument("--socks-host", required=True)
    parser.add_argument("--socks-port", required=True, type=int)
    parser.add_argument("--target-port", required=True, type=int)
    parser.add_argument("--timeout", type=float, default=1.5)
    args = parser.parse_args()

    expect_udp_associate_host_mismatch_allowed(args.socks_host, args.socks_port, args.timeout, args.target_port)
    print("socks5 udp associate host mismatch allowed ok")

    expect_udp_associate_domain_allowed(args.socks_host, args.socks_port, args.timeout, args.target_port)
    print("socks5 udp associate domain allowed ok")

    expect_udp_domain_encoded_target_ok(args.socks_host, args.socks_port, args.timeout, args.target_port)
    print("socks5 udp domain encoded target ok")

    expect_udp_short_packet_ignored_then_recover(args.socks_host, args.socks_port, args.timeout, args.target_port)
    print("socks5 udp short packet ignored and recovered ok")

    expect_udp_invalid_atyp_ignored_then_recover(args.socks_host, args.socks_port, args.timeout, args.target_port)
    print("socks5 udp invalid atyp ignored and recovered ok")

    expect_udp_zero_domain_len_ignored_then_recover(args.socks_host, args.socks_port, args.timeout, args.target_port)
    print("socks5 udp zero domain ignored and recovered ok")

    expect_udp_request_port_constraint(args.socks_host, args.socks_port, args.timeout, args.target_port)
    print("socks5 udp request port ignored ok")

    expect_udp_bound_peer_rebind_ignored(args.socks_host, args.socks_port, args.timeout, args.target_port)
    print("socks5 udp bound peer rebind ignored ok")

    return 0


if __name__ == "__main__":
    sys.exit(main())
