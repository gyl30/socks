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
    data = await reader.readexactly(size)
    return data


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
    lines = header_text.split("\r\n")
    if not lines or not lines[0].startswith("HTTP/1."):
        raise RuntimeError(f"invalid status line {lines[:1]}")
    parts = lines[0].split()
    if len(parts) < 2 or parts[1] != "200":
        raise RuntimeError(f"unexpected status line {lines[0]}")

    content_length = None
    for line in lines[1:]:
        if not line:
            continue
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


async def run_request(args):
    reader, writer = await asyncio.open_connection(args.socks_host, args.socks_port)
    try:
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

        request = (
            f"GET {args.path} HTTP/1.1\r\n"
            f"Host: {args.target_host}:{args.target_port}\r\n"
            "Connection: close\r\n"
            "User-Agent: socks5-load-test\r\n"
            "\r\n"
        ).encode("utf-8")
        writer.write(request)
        await writer.drain()
        return await read_http_response(reader)
    finally:
        writer.close()
        await writer.wait_closed()


async def worker(worker_id, args):
    total_bytes = 0
    for _ in range(args.requests_per_worker):
        total_bytes += await run_request(args)
    return worker_id, total_bytes


async def main_async(args):
    started_at = time.perf_counter()
    tasks = [asyncio.create_task(worker(worker_id, args)) for worker_id in range(args.concurrency)]
    results = await asyncio.gather(*tasks)
    duration = time.perf_counter() - started_at
    total_bytes = sum(worker_bytes for _worker_id, worker_bytes in results)
    total_requests = args.concurrency * args.requests_per_worker
    mib = total_bytes / (1024.0 * 1024.0)
    throughput = mib / duration if duration > 0 else 0.0
    print(f"connections={total_requests}")
    print(f"bytes={total_bytes}")
    print(f"duration_seconds={duration:.3f}")
    print(f"throughput_mib_per_s={throughput:.2f}")


def main():
    parser = argparse.ArgumentParser(description="Concurrent SOCKS5 TCP load generator")
    parser.add_argument("--socks-host", required=True)
    parser.add_argument("--socks-port", required=True, type=int)
    parser.add_argument("--target-host", required=True)
    parser.add_argument("--target-port", required=True, type=int)
    parser.add_argument("--path", required=True)
    parser.add_argument("--concurrency", type=int, default=32)
    parser.add_argument("--requests-per-worker", type=int, default=1)
    args = parser.parse_args()
    asyncio.run(main_async(args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
