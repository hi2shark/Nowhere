# Configuration Reference

The Portal is configured by one URL.

```text
portal://<shared-key>@<listen-host>:<listen-port>?log=<level>&tls=<mode>&crt=<path>&key=<path>&net=<mode>&spec=<spec>&alpn=<alpn>&rate=<mbps>&etar=<mbps>&dial=<ip-or-auto>&socks=<proxy>
```

The URL username is the shared key. A password component is not supported. The
listen port and a non-empty shared key are required. Unknown query parameters
are ignored.

Use percent encoding for reserved URL characters in the shared key, `spec`,
`alpn`, SOCKS credentials, and file paths.

## Input Rules

The shared key, `spec`, and `alpn` are percent-decoded as UTF-8. A literal `+`
in `spec` or `alpn` remains `+`; it is not converted to a space. If a query key
appears more than once, the first occurrence is used, except that duplicate
`socks` parameters are rejected.

| Input | Requirement | Decoded UTF-8 byte length |
| --- | --- | --- |
| shared key | Required and non-empty | `1..255` |
| `spec` | Optional; empty means omitted | `1..255` when non-empty |
| `alpn` | Optional; empty means omitted | `1..255` when non-empty |
| SOCKS username | Required when SOCKS authentication is configured | `1..255` |
| SOCKS password | Required when SOCKS authentication is configured | `1..255` |

## Parameters

| Parameter | Default | Semantics |
| --- | --- | --- |
| `log` | `info` | `none`, `debug`, `info`, `warn`, `error`, or `event`. An unknown value selects `info`. |
| `tls` | `1` | `1` creates an in-memory self-signed certificate. `2` loads PEM files from `crt` and `key`. `0` and all other values are rejected. |
| `crt` | Empty | PEM certificate chain used by `tls=2`. |
| `key` | Empty | PEM private key used by `tls=2`. |
| `net` | `mix` | Selects ingress transports: `tcp` enables TLS/TCP, `udp` enables QUIC/UDP, and `mix` enables both. Missing and empty values select `mix`. |
| `spec` | `auto` | Seed for v1 authentication material, deterministic padding, and field order. |
| `alpn` | `now/1` | TLS and QUIC ALPN value. It does not alter authentication, padding, or frame layout. |
| `rate` | `0` | Client-to-target traffic limit in Mbps. |
| `etar` | `0` | Target-to-client traffic limit in Mbps. |
| `dial` | `auto` | Local IP literal for outbound TCP and UDP sockets. Empty, invalid, hostname, and `auto` values select the operating-system default. |
| `socks` | `none` | SOCKS5 outbound proxy as `host:port` or `user:pass@host:port`. Missing, empty, and `none` disable proxying. IPv6 endpoints require brackets. |

`rate` and `etar` accept positive decimal integers. Zero, a negative value, an
invalid value, or omission disables the corresponding direction. The conversion
is:

```text
bytes_per_second = mbps * 125000
```

## Transport Capabilities

`net` selects the listener transport. It does not directly select the proxied
traffic type.

| Listener transport | TCP proxy traffic | UDP proxy traffic |
| --- | --- | --- |
| TLS/TCP (`net=tcp`) | One TCP relay per authenticated connection | One UoT flow per authenticated connection |
| QUIC/UDP (`net=udp`) | One TCP relay per bidirectional stream | Multiplexed QUIC DATAGRAM flows |
| Both (`net=mix`) | Both paths above | Both paths above |

UoT has no separate Portal setting. A compatible client selects it inside an
authenticated TLS/TCP connection by using the reserved UoT request target and
then sending length-prefixed UDP packets. See the
[protocol specification](protocol.md#92-udp-over-tcp-uot) for the wire format.

## Listener Address Rules

An empty listen host binds separate IPv4 and IPv6 wildcard sockets on the same
port for each selected transport:

```text
portal://secret@:2077
```

Bind one address family explicitly when required:

```text
portal://secret@0.0.0.0:2077
portal://secret@[::]:2077
```

An IP literal binds that address. A hostname is resolved and the first resolved
address is used. All selected sockets must bind before the Portal begins
accepting traffic. In `net=mix`, a bind failure in either TCP or UDP fails
startup.

## TLS Modes

`tls=1` generates a new self-signed certificate for `localhost` when the Portal
starts:

```text
portal://secret@:2077?tls=1
```

Clients must explicitly trust or pin this mode. The generated certificate is
not stable across restarts.

`tls=2` loads a PEM certificate chain and private key:

```text
portal://secret@:2077?tls=2&crt=/etc/nowhere/cert.pem&key=/etc/nowhere/key.pem
```

Both files must be valid at startup. The same certificate and ALPN are used for
TLS/TCP and QUIC.

Plaintext `tls=0` is not supported.

## Spec and ALPN

`spec` and `alpn` are separate controls.

```text
effective_spec = decoded first `spec` value when non-empty, otherwise "auto"
effective_alpn = decoded first `alpn` value when non-empty, otherwise "now/1"
```

Changing `spec` changes the v1 authentication constants, deterministic
padding, and field order. Changing `alpn` changes TLS and QUIC negotiation
only. Peers must agree on both values to interoperate.

## Outbound Source Address

`dial` optionally binds outbound sockets to a local IP address:

```text
portal://secret@:2077?dial=192.0.2.10
portal://secret@:2077?dial=2001:db8::10
```

Only IP literals are accepted. `auto`, an empty value, a hostname, or an
invalid address lets the operating system select the source address. When an IP
is set, the Portal considers only target addresses from the same address
family.

When `socks` is enabled, `dial` instead binds the TCP control/CONNECT
connections and UDP relay sockets used to reach the proxy. It does not bind a
direct connection to the final target.

## SOCKS5 Outbound Proxy

SOCKS5 proxying applies to every outbound target, including loopback and
private addresses:

```text
portal://secret@:2077?socks=proxy.example:1080
portal://secret@:2077?socks=user:pass@proxy.example:1080
portal://secret@:2077?socks=user:p%40ss@[2001:db8::10]:1080
```

Without credentials, the Portal offers only the SOCKS5 no-authentication
method. With credentials, it offers only username/password authentication and
does not permit a downgrade to no authentication. Target hostnames are sent to
the proxy without local resolution. The proxy endpoint itself is resolved by
the Portal.

TCP relays use CONNECT. Each QUIC DATAGRAM or UoT flow owns a separate UDP
ASSOCIATE control connection and relay socket. SOCKS5 UDP fragmentation is not
supported; fragmented responses are discarded. A proxy error closes the
current flow and never falls back to a direct target connection.

The startup URL displays only the SOCKS endpoint. Credentials are omitted, so
an authenticated startup URL is intentionally not a round-trippable copy of
the command line.

## Logging Level

The default level is `info`:

```text
portal://secret@:2077?log=info
```

Use `event` when only the machine-readable checkpoint records should be
emitted:

```text
portal://secret@:2077?log=event
```

Use `none` only when another supervisor captures readiness and failure state.

## Examples

Dual-stack mixed service with defaults:

```text
portal://secret@:2077
```

TLS/TCP-only ingress, including TCP relay and UoT:

```text
portal://secret@:2077?net=tcp
```

QUIC-only ingress, including stream relay and DATAGRAM UDP:

```text
portal://secret@:2077?net=udp
```

PEM certificate with event logs:

```text
portal://secret@:2077?log=event&tls=2&crt=/etc/nowhere/cert.pem&key=/etc/nowhere/key.pem
```

Directional limits:

```text
portal://secret@:2077?rate=100&etar=200
```

Authenticated SOCKS5 outbound routing:

```text
portal://secret@:2077?socks=user:pass@proxy.example:1080
```
