# Nowhere

> **One spec. Nowhere else the same.**

Most relay protocols look the same wherever they run. Nowhere does not.

Nowhere is an encrypted relay protocol for TCP and UDP. The client and Portal
use the same shared key and a compact `spec` to generate matching authentication
and message layouts. The `spec` is never sent over the connection. Change it,
and Nowhere keeps the same features and behavior while using a different layout
for that deployment.

<div align="center">
  <img src="assets/nowhere.png" width="640" alt="Nowhere">
</div>

## Highlights

- **A protocol shape defined by `spec`.** Authentication identity, padding, and
  frame order are derived independently by both peers. The `spec` is never sent,
  and no profile registry or extra negotiation is required.
- **TLS/TCP and QUIC/UDP on one port.** A Portal can listen on both transports at
  the same time, with TLS 1.3 and the same authentication model throughout.
- **TCP and UDP over either transport.** TCP uses dedicated TLS connections or
  QUIC streams; UDP uses UoT when only TCP is available or QUIC DATAGRAM when it
  can use native UDP.
- **Observable and controllable by design.** EVENT checkpoints expose pools,
  active flows, and byte counters, while directional rate limits and runtime
  controls keep the service operator-friendly.
- **Ready for centralized management.** Run the Portal directly or manage its
  lifecycle, persistent configuration, logs, and live metrics through OpenCtrl's
  REST API and Server-Sent Events.
- **Hardened before authentication.** QUIC Retry, bounded pre-authentication
  admission, jittered authentication deadlines, and disabled 0-RTT reduce work
  and information exposure before a client is trusted.

## Transports

| Traffic | TLS/TCP | QUIC/UDP |
| --- | --- | --- |
| TCP | Dedicated encrypted connection | Bidirectional stream |
| UDP | Length-prefixed UDP-over-TCP | QUIC DATAGRAM |

A single Portal URL can enable TLS/TCP, QUIC/UDP, or both on the same port.

## Quick Start

Download a Linux binary from
[Releases](https://github.com/NodePassProject/Nowhere/releases), or run from
source with a stable Rust toolchain:

```bash
cargo run --release --locked -- 'portal://change-me@:2077?spec=nightfall'
```

The URL username is the shared key. The empty host listens on IPv4 and IPv6,
while the default `net=mix` starts TLS/TCP and QUIC/UDP on port `2077`.

The default `tls=1` creates an ephemeral self-signed certificate. Long-lived
deployments should use `tls=2` with a PEM certificate and private key:

```bash
nowhere 'portal://change-me@:2077?tls=2&crt=/etc/nowhere/cert.pem&key=/etc/nowhere/key.pem&spec=nightfall'
```

## Ecosystem

- [OpenCtrl](https://github.com/NodePassProject/OpenCtrl) is a supported
  management layer for Portal lifecycle, durable state, REST/SSE control, logs,
  and EVENT metrics.
- [Anywhere](https://github.com/NodePassProject/Anywhere) is a supported native
  client for TLS/TCP and QUIC/UDP, including TCP relay, QUIC DATAGRAM, and UoT.

Additional core and client integrations are planned.

## Documentation

- [Configuration reference](docs/configuration.md)
- [Documentation index](docs/README.md)
- [Integration guide](docs/integrations.md)
- [Operations guide](docs/operations.md)
- [Protocol specification](docs/protocol.md)
- [Quick start](docs/quick-start.md)
- [Security model](docs/security.md)

## Development

```bash
cargo fmt --all -- --check
cargo test --locked
cargo clippy --all-targets -- -D warnings
cargo build --release --locked
```

Nowhere uses the Rust 2024 edition.

## Contributing

[Issues](https://github.com/NodePassProject/Nowhere/issues) and focused pull
requests are welcome. Protocol changes must update the test vectors and
protocol specification in the same commit.

## License

Nowhere is licensed under the [GNU General Public License v3.0](LICENSE).
Distributions of original or modified binaries must comply with the GPLv3
source and notice requirements.

---

© 2026 NodePassProject. All rights reserved.
