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

`MODE` is `0` for `net=mix`, `1` for `net=tcp`, and `2` for `net=udp`. `PING`
remains fixed in v1. `NOW_REPORT_INTERVAL` controls only local record emission;
it does not send transport keepalive packets.

Carrier health and routing counters are emitted separately:

```text
LINK_STATUS|TCP=<lanes>|UDP=<sessions>|PAIRS=<sessions>|UPTCP=<payload-bytes>|UPUDP=<payload-bytes>|DOWNTCP=<payload-bytes>|DOWNUDP=<payload-bytes>
```

`TCP` counts authenticated TLS lanes, `UDP` authenticated QUIC sessions, and
`PAIRS` logical sessions with both carriers ready. Directional byte fields
count payload after Nowhere framing is removed.

## Rate Limits

`rate` limits client-to-target traffic. `etar` limits target-to-client traffic.
Each relay session (TCP relay, paired TCP relay, UoT, paired UDP flow) gets its
**own** token bucket built from the configured `rate`/`etar`, so concurrent
flows do not contend on a single shared limiter — the aggregate throughput of N
parallel flows scales as N × (per-flow ceiling), not the per-flow ceiling alone.
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
congestion control. Leaving both unset (the default, `rate=0&etar=0`) disables
the limiter entirely (unlimited).

## Concurrent-Speedtest Troubleshooting

When `net=tcp` (TLS/TCP carriers) shows multi-thread speedtest anomalies while
single-thread or `VLESS+WS+TLS` work fine, use this procedure instead of
guessing at the network stack.

### 1. Enable debug logging

- Server: run with debug log level. Watch `relay_*` events and the periodic
  `CHECK_POINT|...|POOL=...|TCPS=...|TCPTX=...` and `LINK_STATUS|...` records.
- Client (mihomo/meta-kernel-nowhere): set `log-level: debug` and grep for
  `[Nowhere] [carrier]`. Each carrier prints its lifecycle:
  `flow_start` → `dial_start` → `auth_ok` → `request_sent ... consumed=true`
  → `relay_start` → `relay_end ... rx_bytes=... tx_bytes=... close_reason=...`.

### 2. Confirm one carrier per flow

In a multi-thread speedtest the client log must show a **distinct `carrier_id`**
for every concurrent `flow_id`. Two active flows sharing one `carrier_id`, or a
`consumed` carrier being borrowed again, is reported as
`illegal transition ... consumed-carrier reuse ...` at WARN level — that is a
bug, not a config issue.

On the server, `CHECK_POINT`'s `TCPS` should rise markedly under multi-thread
load (one TCP relay session per flow). If `TCPS` stays at single-thread levels
the client is not opening independent carriers.

### 3. Isolate the warm pool

Set the client outbound option `pool: 0` (equivalent to disabling preconnect:
every flow dials its own carrier). Re-run the multi-thread speedtest and
compare with `pool: 5`. If `pool: 0` is healthy but `pool: 5` is not, the issue
is in warm-pool state management; if both misbehave, look at per-flow carrier
exclusivity or download-direction write backpressure (server
`write_block_duration` / `read_block_duration` debug lines).

### 4. Confirm rate/etar are not capping aggregate throughput

`rate`/`etar` are now applied per flow, so they should not collapse multi-thread
totals below single-thread. To rule them out entirely, run the server with
**no** `rate`/`etar` query parameters (the default). If a configured `rate` or
`etar` still correlates with the anomaly, double-check that each flow builds an
independent limiter (the `relay_start limiter_per_flow=...` debug line shows the
configured rates).

### 5. Separate TCP relay from UoT (HTTP/3 / QUIC)

Browsers may reach `speed.cloudflare.com` over HTTP/3 (UDP/443). In Chrome
DevTools → Network, check the `Protocol` column for `h3`. If present, disable
QUIC (`chrome://flags/#enable-quic`) and re-test:

- recovers → investigate UoT (UDP-over-TCP) on the `net=tcp` matrix;
- still broken → the problem is in plain TCP relay concurrency, not UoT.

## QUIC Runtime Behavior

The Portal:

- enables QUIC DATAGRAM;
- requires QUIC Retry before accepting an incoming connection;
- starts pre-authenticated connections with one bidirectional stream and 64 KiB
  of connection-level receive credit;
- raises the bidirectional-stream limit to `NOW_QUIC_MAX_STREAMS` after
  authentication;
- dispatches each DATAGRAM UDP flow to an independent bounded worker so target
  dialing and rate-limit waits do not block unrelated flows;
- drops new DATAGRAM requests when the per-flow queue, per-connection byte
  budget, or per-connection flow limit is full;
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
| `NOW_QUIC_MAX_UDP_FLOWS` | `256` | Maximum QUIC DATAGRAM UDP flows per authenticated connection. |
| `NOW_QUIC_UDP_QUEUE_BYTES` | `4194304` | Maximum queued QUIC DATAGRAM bytes per authenticated connection. |
| `NOW_MAX_PENDING_FLOW_PAIRS` | `1024` | Maximum pending asymmetric flow pairs per session. |
| `NOW_FLOW_PAIR_TIMEOUT` | `5s` | Timeout for an unmatched flow half. |
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
use the defaults above. `NOW_QUIC_MAX_UDP_FLOWS` and
`NOW_QUIC_UDP_QUEUE_BYTES` must be positive; zero or invalid values use their
defaults and emit a warning. Other integer controls must be non-negative.

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
