# Quick Start

This guide builds and starts the Nowhere v1 Portal from source.

## Requirements

- Rust toolchain with Rust 2024 edition support.
- A host that can bind the chosen TCP and/or UDP listener port.
- A client implementation that speaks Nowhere v1.

## Build

```bash
cargo build --release --locked
```

The release binary is:

```text
target/release/nowhere
```

Inspect the command-line surface:

```bash
./target/release/nowhere --help
./target/release/nowhere --version
```

## Start a Local Portal

```bash
./target/release/nowhere 'portal://secret@:2077'
```

This starts the Portal with these effective defaults:

| Setting | Effective value |
| --- | --- |
| shared key | `secret` |
| listen host | empty host, dual-stack wildcard |
| listen port | `2077` |
| `log` | `info` |
| `tls` | `1`, generated self-signed certificate |
| `net` | `mix`, TLS/TCP and QUIC/UDP listeners |
| `spec` | `auto` |
| `alpn` | `now/1` |
| `rate` | `0`, disabled |
| `etar` | `0`, disabled |
| `dial` | `auto` |
| `socks` | `none`, direct outbound connections |

The startup log prints the effective URL after parsing. Treat that line as the
operator-facing source of truth for the running process.

## Bind a Specific Address

Bind IPv4 only:

```bash
./target/release/nowhere 'portal://secret@0.0.0.0:2077'
```

Bind IPv6 only:

```bash
./target/release/nowhere 'portal://secret@[::]:2077'
```

Use `net=tcp` or `net=udp` when only one transport should listen:

```bash
./target/release/nowhere 'portal://secret@:2077?net=tcp'
./target/release/nowhere 'portal://secret@:2077?net=udp'
```

These values select ingress transports rather than proxy payload types.
`net=tcp` carries TCP relays and UDP-over-TCP (UoT). `net=udp` carries TCP
relays on QUIC bidirectional streams and UDP flows in QUIC DATAGRAM frames.

## Use a PEM Certificate

The default `tls=1` mode creates a new self-signed certificate at startup. Use
`tls=2` when the Portal should load a certificate chain and private key from
disk:

```bash
./target/release/nowhere 'portal://secret@:2077?tls=2&crt=/etc/nowhere/cert.pem&key=/etc/nowhere/key.pem'
```

Both files must be valid at startup. Certificate reloads are attempted during
ClientHello handling after `NOW_RELOAD_INTERVAL` has elapsed.

## Stop

Send `SIGINT` with `Ctrl-C`. The Portal closes listeners, closes active
connections, waits up to `NOW_SHUTDOWN_TIMEOUT` for QUIC endpoints to become
idle, resets active rate limiters, flushes the logger, and exits.

## Next Steps

- Read [configuration.md](configuration.md) for the full URL contract.
- Read [operations.md](operations.md) before exposing a long-running service.
- Read [security.md](security.md) before choosing a TLS trust policy.
