#!/usr/bin/env python3

import argparse
import functools
import http.server


class threaded_http_server(http.server.ThreadingHTTPServer):
    request_queue_size = 128
    daemon_threads = True


def main() -> int:
    parser = argparse.ArgumentParser(description="HTTP test server with an explicit backlog")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--directory", required=True)
    args = parser.parse_args()

    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=args.directory)
    with threaded_http_server((args.host, args.port), handler) as server:
        server.serve_forever()


if __name__ == "__main__":
    raise SystemExit(main())
