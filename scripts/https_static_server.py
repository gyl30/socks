#!/usr/bin/env python3

import argparse
import http.server
import signal
import ssl
import sys


running = True


def handle_signal(_signum, _frame):
    global running
    running = False


class static_https_handler(http.server.BaseHTTPRequestHandler):
    server_version = "socks-integration-https/1.0"
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = self.server.response_body
        sys.stdout.write(f"request path={self.path}\n")
        sys.stdout.flush()

        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        sys.stdout.write(f"http {self.client_address[0]} {format % args}\n")
        sys.stdout.flush()


class threaded_https_server(http.server.ThreadingHTTPServer):
    daemon_threads = True


def build_parser():
    parser = argparse.ArgumentParser(description="Minimal HTTPS origin server for integration tests")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--certfile", required=True)
    parser.add_argument("--keyfile", required=True)
    parser.add_argument("--response-text", default="ok-https")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    httpd = threaded_https_server((args.host, args.port), static_https_handler)
    httpd.response_body = (args.response_text + "\n").encode("utf-8")
    httpd.timeout = 0.5

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=args.certfile, keyfile=args.keyfile)

    def log_sni(_ssl_socket, server_name, _ssl_context):
        sys.stdout.write(f"sni={server_name or 'empty'}\n")
        sys.stdout.flush()

    context.set_servername_callback(log_sni)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    sys.stdout.write(f"ready {args.host}:{args.port}\n")
    sys.stdout.flush()

    try:
        while running:
            httpd.handle_request()
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

