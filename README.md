# socks

A C++23 proxy and relay playground focused on SOCKS5, transparent proxying, TUN-based traffic capture, and REALITY-style encrypted proxy transport.

> Status: experimental / work in progress. The project is under active development and the configuration format, protocol details, and runtime behavior may change.

## Overview

`socks` is a configurable network proxy daemon. It accepts traffic from multiple inbound types, routes each request through a rule-based router, and forwards it through direct, SOCKS, or REALITY-based outbound transports.

The project is designed around small protocol/session components and explicit flow modules so that TCP, UDP, SOCKS, TPROXY, TUN, and REALITY paths can share routing and relay logic without duplicating session behavior.

## Features

- SOCKS5 inbound support
  - TCP `CONNECT`
  - UDP `ASSOCIATE`
- SOCKS outbound support
- Direct outbound support
- REALITY-style inbound and outbound transport
- Linux transparent proxy support through TPROXY
- TUN inbound support for packet-based traffic capture
- TCP and UDP routing through a shared router
- Domain/IP/inbound based routing rules
- Explicit `block` routing result
- Per-session TCP and UDP relay logic
- Idle timeout handling
- Structured logging and trace-oriented session behavior
- CMake-based build system
- CI coverage for Linux, macOS, and Windows builds
- Regression, integration, sanitizer, and fuzzing-oriented test infrastructure

## Architecture

At a high level, traffic flows through four layers:

```text
Application traffic
    ↓
Inbound: SOCKS5 / TPROXY / TUN / REALITY
    ↓
Flow: tcp_connect_flow / udp_session_flow
    ↓
Router: first-match rule selection
    ↓
Outbound: direct / SOCKS / REALITY / block
```

The current implementation intentionally keeps these boundaries clear:

- `router` maps a normalized request context to an outbound decision.
- `tcp_connect_flow` and `udp_session_flow` normalize inbound requests and create outbound paths.
- `*_session` objects own protocol state, timeout behavior, close reasons, and trace events.
- `stream_relay` and `datagram_relay` only move data and enforce idle watchdog behavior.
- REALITY proxy connections are not multiplexed; one proxy TCP or UDP session maps to one outer REALITY connection.

More design notes are available in:

- [`doc/flow.md`](doc/flow.md)
- [`doc/invariants.md`](doc/invariants.md)
- [`doc/component.uml`](doc/component.uml)
- [`doc/sequence.uml`](doc/sequence.uml)
- [`doc/class.uml`](doc/class.uml)

## Supported platforms

| Platform | SOCKS | TUN | TPROXY | Notes |
| --- | --- | --- | --- | --- |
| Linux | Yes | Yes | Yes | Main development target |
| macOS | Yes | Yes | No | Build target in CI |
| Windows | Yes | Yes | No | Build target in CI; uses Windows networking libraries |

TPROXY is Linux-specific.

## Requirements

- CMake 3.16+
- C++23 compiler
- Boost 1.89+
- OpenSSL
- Brotli
- Python 3, for integration tests
- Ninja, recommended

The CI workflow currently builds against Boost 1.89.0, OpenSSL 3.6.0, and Brotli 1.1.0.

## Build

Clone with submodules:

```bash
git clone --recursive https://github.com/gyl30/socks.git
cd socks
```

Configure and build:

```bash
cmake -S . -B build -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DENABLE_ASAN=OFF

cmake --build build --target socks --parallel
```

For local debugging, the default build type is `Debug` when no build type is specified. AddressSanitizer and UndefinedBehaviorSanitizer are enabled by default when using a Clang toolchain unless disabled with `-DENABLE_ASAN=OFF`.

## Build options

Common CMake options:

| Option | Default | Description |
| --- | --- | --- |
| `ENABLE_ASAN` | `ON` | Enable AddressSanitizer and UndefinedBehaviorSanitizer with Clang |
| `ENABLE_TSAN` | `OFF` | Enable ThreadSanitizer with Clang |
| `ENABLE_LSAN` | `OFF` | Enable LeakSanitizer with Clang |
| `ENABLE_FUZZ` | `OFF` | Build libFuzzer targets; requires Clang |
| `ENABLE_COVERAGE` | `OFF` | Enable coverage instrumentation |
| `ENABLE_STATIC_LINK` | `OFF` | Prefer static linking for the executable and third-party dependencies |
| `ENABLE_STRICT_WARNINGS` | `OFF` | Enable additional compiler warnings |

Example sanitizer build:

```bash
cmake -S . -B build-asan -GNinja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DENABLE_ASAN=ON

cmake --build build-asan --parallel
ctest --test-dir build-asan --output-on-failure
```

Example fuzz build:

```bash
cmake -S . -B build-fuzz -GNinja \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DENABLE_FUZZ=ON

cmake --build build-fuzz --target ch_parser_fuzz --parallel
```

## Usage

```bash
./build/socks -c config/local-client.json
```

Other commands:

```bash
# Generate an X25519 key pair for REALITY-style configuration
./build/socks x25519

# Print the default configuration
./build/socks config
```

## Configuration

The daemon is configured through JSON. Example files are provided under [`config/`](config/):

- [`config/local-client.json`](config/local-client.json)
- [`config/local-server.json`](config/local-server.json)
- [`config/direct_domain.txt`](config/direct_domain.txt)
- [`config/direct_ip.txt`](config/direct_ip.txt)
- [`config/proxy_domain.txt`](config/proxy_domain.txt)
- [`config/block_domain.txt`](config/block_domain.txt)
- [`config/block_ip.txt`](config/block_ip.txt)

A simplified client-side shape looks like this:

```json
{
  "workers": 1,
  "log": {
    "level": "info",
    "file": "config/local-client.log"
  },
  "inbounds": [
    {
      "type": "socks",
      "tag": "socks-in",
      "settings": {
        "host": "127.0.0.1",
        "port": 1080,
        "auth": false
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "routing": [
    {
      "type": "inbound",
      "values": ["socks-in"],
      "out": "direct"
    }
  ],
  "timeout": {
    "read": 10,
    "write": 10,
    "connect": 5,
    "idle": 60
  }
}
```

Generate the complete default configuration with:

```bash
./build/socks config
```

## Local smoke test

Start a simple local SOCKS listener using the sample configuration:

```bash
./build/socks -c config/local-client.json
```

Then point a SOCKS-capable client to:

```text
127.0.0.1:1080
```

For example:

```bash
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

Depending on the selected configuration, traffic may be routed directly, sent through another SOCKS outbound, or encapsulated through a REALITY-style outbound.

## Testing

Run the CTest suite:

```bash
ctest --test-dir build --output-on-failure
```

The repository contains unit-style regression tests and integration-style tests for protocol guards, REALITY handshake behavior, routing consistency, UDP transparent sessions, timeout budgets, trace storage, and resource stability.

Some tests require loopback networking behavior, and TPROXY/TUN related tests may require Linux-specific capabilities or privileges.

The shell-based SOCKS5 smoke test can also be run manually:

```bash
bash scripts/test_socks5.sh build/socks
```

## Development notes

Before changing protocol or session behavior, read [`doc/invariants.md`](doc/invariants.md). Important invariants include:

- Routing is first-match.
- Domain rules are exact matches, not suffix or wildcard matches.
- `block` is an explicit routing result.
- TCP proxy frames follow a fixed request/reply/data/shutdown sequence.
- UDP proxy frames preserve datagram boundaries.
- REALITY proxy transport does not currently use mux or connection reuse.

Suggested checks before sending a change:

```bash
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

When modifying a specific subsystem, also update or add the corresponding regression/integration test.

## Repository layout

```text
.github/workflows/     CI workflow
config/                Example configuration and routing rule files
doc/                   Architecture notes and UML diagrams
docker/                Container-related development files
fuzz/                  libFuzzer targets
reality/               REALITY handshake, policy, and session code
scripts/               Regression and integration tests
third/                 Third-party source dependencies / submodules
tls/                   TLS parsing, record, transcript, and crypto helpers
*.cpp, *.h             Core proxy, routing, session, and relay implementation
```

## Security notice

This project handles network traffic and implements security-sensitive protocol behavior. It should be treated as experimental unless you have reviewed the code and configuration for your deployment environment.

Do not use example keys from `config/` in production. Generate your own key pair with:

```bash
./build/socks x25519
```

## Contributing

Issues and pull requests are welcome. For meaningful changes, please include:

- A short description of the behavior change
- Relevant configuration examples, if applicable
- Regression or integration tests for protocol/session behavior
- Notes about platform-specific behavior, especially for Linux TPROXY or TUN changes

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.

