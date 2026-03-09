#!/usr/bin/env python3

import argparse
import asyncio
import signal
import sys
from urllib import parse


running = True


def handle_signal(_signum, _frame):
    global running
    running = False


def parse_positive_int(query, key, default_value):
    value = query.get(key, [str(default_value)])[0]
    try:
        parsed = int(value)
    except ValueError as exc:
        raise RuntimeError(f"invalid integer {key}={value}") from exc
    if parsed < 0:
        raise RuntimeError(f"invalid negative integer {key}={value}")
    return parsed


async def read_request_target(reader):
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = await asyncio.wait_for(reader.read(4096), timeout=5.0)
        if not chunk:
            raise RuntimeError("unexpected eof before request")
        data.extend(chunk)
        if len(data) > 65536:
            raise RuntimeError("request header too large")

    header_end = data.index(b"\r\n\r\n") + 4
    request_text = data[:header_end].decode("iso-8859-1")
    request_line = request_text.split("\r\n", 1)[0]
    parts = request_line.split()
    if len(parts) != 3:
        raise RuntimeError(f"invalid request line {request_line!r}")
    if parts[0] != "GET":
        raise RuntimeError(f"unsupported method {parts[0]!r}")
    return parse.urlsplit(parts[1])


async def write_headers(writer, body_bytes):
    header = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/octet-stream\r\n"
        f"Content-Length: {body_bytes}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")
    writer.write(header)
    await writer.drain()


async def write_body(writer, body_bytes, chunk_size, chunk_interval_ms):
    sent = 0
    payload = b"socks5-slow-http-server-" * 4096
    while sent < body_bytes:
        piece_size = min(chunk_size, body_bytes - sent)
        writer.write(payload[:piece_size])
        await writer.drain()
        sent += piece_size
        if chunk_interval_ms > 0 and sent < body_bytes:
            await asyncio.sleep(chunk_interval_ms / 1000.0)


async def handle_slow_success(writer, query):
    header_delay_ms = parse_positive_int(query, "header_delay_ms", 0)
    body_bytes = parse_positive_int(query, "body_bytes", 65536)
    chunk_size = max(1, parse_positive_int(query, "chunk_size", 4096))
    chunk_interval_ms = parse_positive_int(query, "chunk_interval_ms", 0)

    if header_delay_ms > 0:
        await asyncio.sleep(header_delay_ms / 1000.0)
    await write_headers(writer, body_bytes)
    await write_body(writer, body_bytes, chunk_size, chunk_interval_ms)


async def handle_stall_before_header(writer, query):
    delay_ms = parse_positive_int(query, "delay_ms", 5000)
    body_bytes = parse_positive_int(query, "body_bytes", 1024)

    await asyncio.sleep(delay_ms / 1000.0)
    await write_headers(writer, body_bytes)
    await write_body(writer, body_bytes, min(body_bytes, 4096), 0)


async def handle_stall_mid_body(writer, query):
    body_bytes = parse_positive_int(query, "body_bytes", 65536)
    first_chunk_bytes = parse_positive_int(query, "first_chunk_bytes", 4096)
    stall_ms = parse_positive_int(query, "stall_ms", 5000)
    tail_chunk_size = max(1, parse_positive_int(query, "chunk_size", 4096))
    tail_chunk_interval_ms = parse_positive_int(query, "chunk_interval_ms", 0)

    await write_headers(writer, body_bytes)
    await write_body(writer, min(body_bytes, first_chunk_bytes), max(1, first_chunk_bytes), 0)
    if first_chunk_bytes < body_bytes:
        await asyncio.sleep(stall_ms / 1000.0)
        await write_body(writer, body_bytes - first_chunk_bytes, tail_chunk_size, tail_chunk_interval_ms)


async def handle_request(reader, writer):
    try:
        target = await read_request_target(reader)
        query = parse.parse_qs(target.query)
        if target.path == "/slow-success":
            await handle_slow_success(writer, query)
        elif target.path == "/stall-before-header":
            await handle_stall_before_header(writer, query)
        elif target.path == "/stall-mid-body":
            await handle_stall_mid_body(writer, query)
        elif target.path == "/fast-large":
            await handle_slow_success(writer, query)
        else:
            writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError):
        pass
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        sys.stderr.write(f"slow_http_server request failed {exc}\n")
        sys.stderr.flush()
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def main_async(args):
    server = await asyncio.start_server(handle_request, args.host, args.port)
    async with server:
        while running:
            await asyncio.sleep(0.2)
    server.close()
    await server.wait_closed()


def main():
    parser = argparse.ArgumentParser(description="Slow HTTP server for low-rate and timeout SOCKS5 tests")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    args = parser.parse_args()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    asyncio.run(main_async(args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
