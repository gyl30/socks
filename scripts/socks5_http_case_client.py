#!/usr/bin/env python3

import argparse
import asyncio
import ipaddress
import socket
import struct
import time


def build_connect_request(host, port):
    request = bytearray(b"\x05\x01\x00")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        encoded_host = host.encode("utf-8")
        if not encoded_host or len(encoded_host) > 255:
            raise RuntimeError("invalid domain host")
        request.append(0x03)
        request.append(len(encoded_host))
        request.extend(encoded_host)
    else:
        if address.version == 4:
            request.append(0x01)
        else:
            request.append(0x04)
        request.extend(address.packed)
    request.extend(struct.pack("!H", port))
    return bytes(request)


async def recv_exact(reader, size):
    return await reader.readexactly(size)


async def recv_socks_reply(reader):
    head = await recv_exact(reader, 4)
    atyp = head[3]
    if atyp == 0x01:
        tail = await recv_exact(reader, 6)
    elif atyp == 0x04:
        tail = await recv_exact(reader, 18)
    elif atyp == 0x03:
        domain_len = (await recv_exact(reader, 1))[0]
        tail = bytes([domain_len]) + await recv_exact(reader, domain_len + 2)
    else:
        raise RuntimeError(f"unsupported atyp {atyp}")
    return head + tail


async def open_socks_stream(args):
    reader, writer = await asyncio.open_connection(args.socks_host, args.socks_port)
    raw_socket = writer.get_extra_info("socket")
    if raw_socket is not None and args.recv_buffer > 0:
        raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, args.recv_buffer)

    writer.write(b"\x05\x01\x00")
    await writer.drain()
    method_reply = await recv_exact(reader, 2)
    if method_reply != b"\x05\x00":
        raise RuntimeError(f"unexpected method reply {method_reply!r}")

    writer.write(build_connect_request(args.target_host, args.target_port))
    await writer.drain()
    reply = await recv_socks_reply(reader)
    if reply[1] != 0x00:
        raise RuntimeError(f"connect failed rep={reply[1]}")
    return reader, writer


def build_http_get(args):
    return (
        f"GET {args.path} HTTP/1.1\r\n"
        f"Host: {args.target_host}:{args.target_port}\r\n"
        "Connection: close\r\n"
        "User-Agent: socks5-http-case-client\r\n"
        "\r\n"
    ).encode("utf-8")


async def read_http_response(reader):
    header = bytearray()
    while b"\r\n\r\n" not in header:
        chunk = await reader.read(4096)
        if not chunk:
            raise RuntimeError("unexpected eof before response header")
        header.extend(chunk)
        if len(header) > 65536:
            raise RuntimeError("response header too large")

    header_end = header.index(b"\r\n\r\n") + 4
    raw_header = bytes(header[:header_end])
    body = bytearray(header[header_end:])
    header_text = raw_header.decode("iso-8859-1")
    status_line = header_text.split("\r\n", 1)[0]
    status_parts = status_line.split()
    if len(status_parts) < 2 or status_parts[1] != "200":
        raise RuntimeError(f"unexpected status line {status_line}")

    content_length = None
    for line in header_text.split("\r\n")[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key.lower() == "content-length":
            content_length = int(value.strip())
            break
    if content_length is None:
        raise RuntimeError("missing content-length")

    while len(body) < content_length:
        chunk = await reader.read(content_length - len(body))
        if not chunk:
            raise RuntimeError("unexpected eof before response body")
        body.extend(chunk)
    return content_length


async def run_read_full(args):
    started_at = time.perf_counter()
    reader, writer = await open_socks_stream(args)
    try:
        writer.write(build_http_get(args))
        await writer.drain()
        body_bytes = await read_http_response(reader)
        duration = time.perf_counter() - started_at
        print(f"result=ok bytes={body_bytes} duration_seconds={duration:.3f}")
    finally:
        writer.close()
        await writer.wait_closed()


async def run_send_and_stall(args):
    reader, writer = await open_socks_stream(args)
    try:
        writer.write(build_http_get(args))
        await writer.drain()
        await asyncio.sleep(args.stall_seconds)
        print(f"result=ok stalled_seconds={args.stall_seconds:.3f}")
    finally:
        writer.close()
        await writer.wait_closed()


async def run_handshake_stall_one(args):
    reader, writer = await asyncio.open_connection(args.socks_host, args.socks_port)
    try:
        if args.stage == "greeting-header":
            writer.write(b"\x05")
        elif args.stage == "methods-header":
            writer.write(b"\x05\x01")
        elif args.stage == "request-header":
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            await recv_exact(reader, 2)
            writer.write(b"\x05\x01\x00\x01")
        else:
            raise RuntimeError(f"unsupported stage {args.stage}")
        await writer.drain()
        await asyncio.sleep(args.stall_seconds)
    finally:
        writer.close()
        await writer.wait_closed()


async def run_handshake_stall(args):
    tasks = [asyncio.create_task(run_handshake_stall_one(args)) for _ in range(args.count)]
    await asyncio.gather(*tasks)
    print(f"result=ok stalled_connections={args.count}")


async def main_async(args):
    try:
        if args.mode == "read-full":
            coro = run_read_full(args)
        elif args.mode == "send-and-stall":
            coro = run_send_and_stall(args)
        elif args.mode == "handshake-stall":
            coro = run_handshake_stall(args)
        else:
            raise RuntimeError(f"unsupported mode {args.mode}")

        if args.overall_timeout > 0:
            await asyncio.wait_for(coro, timeout=args.overall_timeout)
        else:
            await coro
        if args.expect_failure:
            raise RuntimeError("expected failure but request succeeded")
        return 0
    except Exception as exc:
        if args.expect_failure:
            print(f"result=expected-failure error={exc}")
            return 0
        raise


def build_parser():
    parser = argparse.ArgumentParser(description="SOCKS5 client helper for slow and timeout test cases")
    parser.add_argument("--mode", required=True, choices=["read-full", "send-and-stall", "handshake-stall"])
    parser.add_argument("--socks-host", required=True)
    parser.add_argument("--socks-port", required=True, type=int)
    parser.add_argument("--overall-timeout", type=float, default=0.0)
    parser.add_argument("--expect-failure", action="store_true")
    parser.add_argument("--recv-buffer", type=int, default=0)
    parser.add_argument("--stall-seconds", type=float, default=0.0)
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--stage", default="greeting-header", choices=["greeting-header", "methods-header", "request-header"])
    parser.add_argument("--target-host", default="127.0.0.1")
    parser.add_argument("--target-port", type=int, default=0)
    parser.add_argument("--path", default="/")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        return asyncio.run(main_async(args))
    except Exception as exc:
        print(f"result=error error={exc}", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
