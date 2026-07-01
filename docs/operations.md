# Operations Guide

This guide covers the behavior that matters after the Portal starts.

## Startup

The Portal validates configuration before accepting traffic. In `net=mix`, TCP
and UDP listeners must both bind successfully. The process logs the effective
startup URL after defaults are applied:

```text
portal::run: starting: portal://:<port>?tls=1&net=mix&spec=auto&alpn=now/1&rate=0&etar=0&dial=auto&socks=none
```

Use this line when comparing intended configuration with runtime behavior. It
prints effective values, not necessarily the exact command-line URL. When
SOCKS5 authentication is configured, this line prints only the proxy endpoint
and never prints the username or password.

## SOCKS5 Outbound Behavior

When `socks` is configured, all TCP and UDP target traffic is routed through
that SOCKS5 server. TCP uses CONNECT. Every QUIC DATAGRAM and UoT flow uses its
own UDP ASSOCIATE control connection and relay socket. Closing the control
connection closes the associated flow.

Target domain names are resolved by the SOCKS5 server. The Portal resolves only
the proxy endpoint and any domain returned by the proxy for its UDP relay. If
`dial` specifies a local IP, proxy addresses and relay sockets must use the same
address family.

Proxy connection, authentication, command, or relay failures close only the
affected Nowhere flow. The Portal never bypasses the configured proxy by
falling back to a direct target connection. TCP proxy setup shares
`NOW_TCP_DIAL_TIMEOUT`; UDP proxy setup shares `NOW_UDP_DIAL_TIMEOUT`.

## Logging

Logs are written to standard output with a local timestamp and severity. Startup
errors are written to standard error.

Available URL log levels:

| Level | Behavior |
| --- | --- |
| `none` | Disable output. |
| `debug` | Emit debug, info, warning, error, and event records. |
| `info` | Emit normal operational logs, warnings, errors, and event records. |
| `warn` | Emit warnings, errors, and event records. |
| `error` | Emit errors and event records. |
| `event` | Emit event records only. |

An unknown `log` value selects `info`.

## Event Records

At startup and then every `NOW_REPORT_INTERVAL`, the Portal emits a checkpoint
record when the active log level includes events:

```text
CHECK_POINT|MODE=0|PING=0ms|POOL=<n>|TCPS=<n>|UDPS=<n>|TCPRX=<bytes>|TCPTX=<bytes>|UDPRX=<bytes>|UDPTX=<bytes>
```

| Field | Meaning |
| --- | --- |
| `POOL` | Authenticated TLS/TCP connections waiting for their first request frame. |
| `TCPS` | Active TCP relay streams. |
| `UDPS` | Active UDP flows across QUIC DATAGRAM and UoT. |
| `TCPRX` | Client-to-target TCP bytes. |
| `TCPTX` | Target-to-client TCP bytes. |
| `UDPRX` | Client-to-target UDP payload bytes. |
| `UDPTX` | Target-to-client UDP payload bytes. |

`MODE` and `PING` remain fixed in v1. `NOW_REPORT_INTERVAL` controls only local
record emission; it does not send transport keepalive packets.

## Rate Limits

`rate` limits client-to-target traffic. `etar` limits target-to-client traffic.
Both are process-wide limits shared across active TLS/TCP and QUIC sessions.
For UoT, only UDP payload bytes are charged; the two-byte packet lengths and
setup framing are not.

```text
portal://secret@:2077?rate=100&etar=200
```

The conversion is:

```text
bytes_per_second = mbps * 125000
```

Limits are enforced above the transport layer. They do not select or tune QUIC
congestion control.

## QUIC Runtime Behavior

The Portal:

- enables QUIC DATAGRAM;
- requires QUIC Retry before accepting an incoming connection;
- starts pre-authenticated connections with one bidirectional stream and 64 KiB
  of connection-level receive credit;
- raises the bidirectional-stream limit to `NOW_QUIC_MAX_STREAMS` after
  authentication;
- raises the connection-level receive credit to 32 MiB after authentication;
- uses 16 MiB per-stream receive credit;
- permits up to 32 MiB of unacknowledged stream data per connection;
- disables unidirectional streams;
- uses BBR congestion control;
- uses `NOW_UDP_IDLE_TIMEOUT` as the QUIC idle timeout; and
- does not send QUIC transport keepalive packets.

QUIC DATAGRAM send and receive buffers are configured to 4 MiB. The UDP socket
send and receive buffers are requested at 4 MiB. Operating systems may clamp
socket buffer requests.

## UoT Runtime Behavior

UoT is available whenever the TLS/TCP listener is enabled; it has no separate
configuration switch. After normal transport authentication, a client sends a
TCP request for the reserved target `uot.nowhere.invalid:0`, one UDP target
setup frame, and then a sequence of two-byte-length-prefixed packets.

Each UoT connection represents one logical UDP flow to one target. Packet
boundaries are preserved, traffic in either direction refreshes
`NOW_UDP_IDLE_TIMEOUT`, and closing the TLS/TCP connection closes the flow.
UoT flows increment `UDPS`, `UDPRX`, and `UDPTX`, not the TCP relay counters.

UoT is useful when QUIC/UDP cannot traverse the network, but TCP head-of-line
blocking applies. Prefer QUIC DATAGRAM when native UDP transport is available
and packet loss must not stall unrelated packets.

## Authentication Deadlines

After a TLS or QUIC handshake completes, authentication uses one absolute
deadline sampled from:

```text
NOW_HANDSHAKE_TIMEOUT * [0.8, 1.2]
```

Successful authentication proceeds immediately. Failed authentication waits
until the sampled deadline. TCP then closes without an application response.
QUIC closes with application code `0x01` and reason `access denied`.

This timing policy keeps common invalid-auth paths less distinguishable while
still bounding resource use.

## Admission Limits

Before authentication, the Portal applies a process-wide admission limit shared
by TCP and QUIC:

| Limit | Value |
| --- | --- |
| Total pre-authenticated connections | `256` |
| Per IPv4 `/32` or IPv6 `/64` | `32` |

A validated QUIC attempt above either limit is ignored. A TCP connection above
either limit is accepted and immediately closed. A slot is released as soon as
authentication succeeds or fails.

## Runtime Controls

| Variable | Default | Purpose |
| --- | --- | --- |
| `NOW_QUIC_MAX_STREAMS` | `1024` | Maximum concurrent QUIC bidirectional streams after authentication. |
| `NOW_TCP_DATA_BUF_SIZE` | `32768` | Buffer size for each TCP relay direction. |
| `NOW_UDP_DATA_BUF_SIZE` | `65536` | UDP target-socket receive buffer size. |
| `NOW_TCP_DIAL_TIMEOUT` | `15s` | TCP target connection timeout. |
| `NOW_UDP_DIAL_TIMEOUT` | `15s` | UDP target connection timeout. |
| `NOW_TCP_READ_TIMEOUT` | `30s` | Grace period after one TCP direction reaches EOF. |
| `NOW_UDP_IDLE_TIMEOUT` | `120s` | QUIC connection and QUIC DATAGRAM/UoT flow idle timeout. |
| `NOW_HANDSHAKE_TIMEOUT` | `5s` | Base authentication deadline before jitter. |
| `NOW_REPORT_INTERVAL` | `5s` | Local checkpoint event interval. |
| `NOW_SHUTDOWN_TIMEOUT` | `5s` | Endpoint idle wait during shutdown. |
| `NOW_RELOAD_INTERVAL` | `3600s` | Minimum interval between PEM reload attempts. |

Duration values accept forms such as `500ms`, `15s`, and `2m`. Invalid values
use the defaults above. Integer controls must be non-negative.

`NOW_SERVICE_COOLDOWN` also exists in the runtime defaults and currently
defaults to `3s`; it is reserved for service-side retry paths.

## Shutdown

`SIGINT` starts graceful shutdown. The Portal:

1. Cancels accept loops.
2. Closes QUIC endpoints and active connections.
3. Waits up to `NOW_SHUTDOWN_TIMEOUT` for endpoints to become idle.
4. Waits for TCP connection tasks inside the same bounded shutdown window.
5. Resets active rate limiters.
6. Emits the shutdown-complete log and flushes the logger.

## Operational Practices

- Run with `tls=2` for long-lived public deployments.
- Put certificates and keys outside the repository and restrict file
  permissions to the service user.
- Keep `log=event` for machine parsing and `log=info` during rollout.
- Use `net=tcp` or `net=udp` when a deployment only needs one ingress transport.
- Prefer explicit listen addresses when running behind a supervisor that
  expects one address family.
- Validate the effective startup URL after every config change.
- Treat `rate` and `etar` as process-wide fairness controls, not per-client
  quotas.
