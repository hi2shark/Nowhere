# Configuration Reference

Nowhere runs one command URL per process. `portal://` starts the relay service;
`vector://` starts the native SOCKS5 client.

## URL Rules

The URL username is the percent-decoded shared key and MUST contain `1..255`
bytes. Password userinfo, paths, and fragments are rejected. Literal `+`
remains `+` rather than being decoded as a space.

Query parsing follows these rules:

- parameters may appear in any order;
- unknown parameters are ignored;
- the first occurrence of a repeated parameter wins;
- absent optional parameters use their defaults;
- an invalid selected value fails startup.

## Portal

```text
portal://<shared-key>@<listen-host>:<port>?net=...&tls=...&crt=...&key=...&alpn=...&rate=...&etar=...&dial=...&socks=...&log=...
```

An empty listen host binds separate IPv4 and IPv6 wildcard sockets. An IP
literal binds only that family. A hostname resolves to its first address.

| Parameter | Default | Rules |
| --- | --- | --- |
| `net` | `mix` | `mix`, `tcp`, or `udp` |
| `tls` | `1` | `1` creates an in-memory certificate; `2` loads PEM files |
| `crt` | omitted | Required and nonempty exactly when `tls=2` |
| `key` | omitted | Required and nonempty exactly when `tls=2` |
| `alpn` | `now/1` | Nonempty decoded value, at most 255 bytes |
| `rate` | `0` | Client-to-target Mbps; nonnegative integer |
| `etar` | `0` | Target-to-client Mbps; nonnegative integer |
| `dial` | `auto` | `auto` or a local IP literal |
| `socks` | `none` | Outbound SOCKS5 endpoint or `none` |
| `log` | `info` | `none`, `debug`, `info`, `warn`, `error`, or `event` |

Portal prints its effective settings in this order:

```text
net -> tls -> alpn -> rate -> etar -> dial -> socks
```

Rate conversion is `Mbps * 125000` bytes per second. Zero disables the
corresponding limiter.

### Outbound SOCKS5

```text
socks=host:port
socks=user:password@host:port
socks=user:p%40ss@[2001:db8::10]:1080
```

With credentials, Portal offers only username/password authentication. Without
credentials, it offers only no-auth. CONNECT handles TCP targets; each UDP flow
owns one UDP ASSOCIATE control connection. Proxy failure never falls back to a
direct route. `socks=` is invalid; omit the parameter or use `socks=none`.

### Portal Examples

```text
portal://secret@:2077
portal://secret@0.0.0.0:2077?net=tcp
portal://secret@:2077?tls=2&crt=/etc/nowhere/cert.pem&key=/etc/nowhere/key.pem
portal://secret@:2077?alpn=now%2Fprivate&rate=100&etar=200
```

## Vector

```text
vector://<shared-key>@<portal-host>:<port>?up=...&down=...&pool=...&sni=...&alpn=...&rate=...&etar=...&socks=...&log=...
```

Portal host, Portal port, and the local `socks` listener are required. Vector
prints its effective settings in this order:

```text
up -> down -> pool -> sni -> alpn -> rate -> etar -> socks
```

| Parameter | Default | Rules |
| --- | --- | --- |
| `up` | `udp` | `tcp` selects TLS/TCP; `udp` selects QUIC |
| `down` | `udp` | `tcp` selects TLS/TCP; `udp` selects QUIC |
| `pool` | `5` for `tcp/tcp` | Nonnegative integer, capped at 256 |
| `sni` | `none` | DNS certificate name; empty or `none` disables verification |
| `alpn` | `now/1` | Must match Portal |
| `rate` | `0` | Local SOCKS-client-to-target Mbps |
| `etar` | `0` | Local target-to-SOCKS-client Mbps |
| `socks` | required | `[user:password@]listen-host:port` |
| `log` | `info` | Same levels as Portal |

The warm pool is active only when both directions use TLS/TCP. `pool=0`
disables preconnection. Values greater than 256 become 256. Every other
carrier pair ignores the supplied pool value and reports `pool=0`.

When `sni` contains a DNS name, Vector loads system roots and verifies both the
certificate chain and name. Empty, omitted, or `none` disables certificate
verification. A domain Portal host may still be sent as ClientHello SNI for
virtual-host routing. Operator output always records the effective value,
including `sni=none`.

The SOCKS listener value cannot be empty, but its host may be empty:

```text
vector://secret@127.0.0.1:2077?socks=127.0.0.1:1080
vector://secret@127.0.0.1:2077?up=tcp&down=tcp&pool=5&socks=:1080
vector://secret@relay.example:2077?sni=relay.example&socks=user:p%40ss@0.0.0.0:1080
```

An empty SOCKS host binds separate IPv4 and IPv6 wildcard listeners. Explicit
wildcards require authentication and network policy when exposed beyond the
local host.

## Runtime Limits

| Variable | Default | Purpose |
| --- | --- | --- |
| `NOW_QUIC_MAX_STREAMS` | `1024` | Authenticated QUIC streams and Vector TCP flow cap |
| `NOW_QUIC_MAX_UDP_FLOWS` | `256` | UDP flows per session and Vector UDP target cap |
| `NOW_QUIC_UDP_QUEUE_BYTES` | `4194304` (4 MiB) | QUIC UDP queue and reassembly byte budget |
| `NOW_TCP_IDLE_POOL_CONNS` | `4096` | Portal authenticated idle TLS lane cap |
| `NOW_MAX_PENDING_PAIRS` | `1024` | Pending split-flow cap per session |
| `NOW_FLOW_PAIR_TIMEOUT` | `15s` | Split-flow pairing deadline |
| `NOW_TCP_DATA_BUF_SIZE` | `32768` (32 KiB) | TCP relay buffer size |
| `NOW_UDP_DATA_BUF_SIZE` | `65536` (64 KiB) | UDP receive buffer size |
| `NOW_TCP_DIAL_TIMEOUT` | `15s` | TCP target connect deadline |
| `NOW_UDP_DIAL_TIMEOUT` | `15s` | UDP target setup deadline |
| `NOW_TCP_READ_TIMEOUT` | `30s` | Opposite-half TCP drain grace |
| `NOW_UDP_IDLE_TIMEOUT` | `2m` | UDP flow and association target idle timeout |
| `NOW_HANDSHAKE_TIMEOUT` | `5s` | Authentication and flow setup deadline |
| `NOW_REPORT_INTERVAL` | `5s` | CHECK_POINT and LINK_STATUS interval |
| `NOW_SERVICE_COOLDOWN` | `3s` | Carrier reconnect delay |
| `NOW_SHUTDOWN_TIMEOUT` | `5s` | Graceful shutdown deadline |
| `NOW_RELOAD_INTERVAL` | `1h` | PEM certificate reload interval |
