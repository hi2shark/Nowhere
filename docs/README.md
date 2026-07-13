# Nowhere Documentation

The documentation is split by job. Read the quick start first if you are
running the reference server. Read the protocol specification first if you are
building a compatible client.

## Transport Map

The `net` parameter selects which ingress transports listen on the configured
port. It does not restrict the Portal to one proxy payload type.

| `net` value | Listener | TCP proxy path | UDP proxy path |
| --- | --- | --- | --- |
| `tcp` | TLS/TCP | Dedicated authenticated connection | UoT on a dedicated authenticated connection |
| `udp` | QUIC/UDP | Bidirectional QUIC stream | QUIC DATAGRAM |
| `mix` | Both | Both paths | Both paths |

UoT uses the reserved request target `uot.nowhere.invalid:0`, followed by one
target setup frame and typed UDP packet/control frames. It is part of the v1 wire
protocol and requires no separate server option.

## Documents

| Document | Scope |
| --- | --- |
| [Configuration reference](configuration.md) | URL shape, query parameters, listener rules, TLS inputs, and examples. |
| [Integration guide](integrations.md) | OpenCtrl management and Anywhere client setup. |
| [Operations guide](operations.md) | Logging, event records, rate limits, runtime controls, shutdown, and deployment habits. |
| [Protocol specification](protocol.md) | Normative v1 wire format, derivation, TCP, QUIC DATAGRAM, UoT, limits, and conformance checks. |
| [Quick start](quick-start.md) | Build, run, and smoke-check a local Portal. |
| [Security notes](security.md) | Shared-key handling, TLS trust, authentication failure behavior, and exposure guidance. |

## Reading Paths

For operators:

1. [Quick start](quick-start.md)
2. [Configuration reference](configuration.md)
3. [Operations guide](operations.md)
4. [Integration guide](integrations.md)
5. [Security notes](security.md)

For client authors:

1. [Protocol specification](protocol.md)
2. [Configuration reference](configuration.md)
3. [Integration guide](integrations.md)
4. [Security notes](security.md)

For release maintainers:

1. [Quick start](quick-start.md)
2. [Operations guide](operations.md)
3. The GitHub release workflow in `.github/workflows/release.yml`

## Style

The docs use the same naming throughout:

- `Portal` means this Rust server.
- `client` means a peer that dials the Portal and opens target flows.
- `shared key` means the URL username after percent decoding.
- `effective_spec` means the resolved `spec` value after defaults.
- `effective_alpn` means the resolved `alpn` value after defaults.
- `UoT` means the UDP-over-TCP packet path carried by one authenticated TLS/TCP connection.
- `rate` is client-to-target traffic.
- `etar` is target-to-client traffic.
