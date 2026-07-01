# Nowhere Protocol v1

## 1. Status and Scope

This document defines version 1 of the Nowhere proxy protocol and the Portal
configuration required by the reference implementation.

Nowhere carries authenticated TCP and UDP proxy traffic over TLS/TCP or QUIC.
TCP uses a dedicated TLS/TCP connection or a QUIC bidirectional stream. UDP
uses QUIC DATAGRAM frames or a length-prefixed UDP-over-TCP (UoT) flow. A shared
key authenticates each transport connection, while a deterministic `spec`
value selects the authentication shape, padding, and field layout.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**,
and **MAY** are to be interpreted as normative requirements.

## 2. Conventions

- All integer fields are unsigned and use network byte order unless stated
  otherwise.
- `u8`, `u16`, and `u64` denote 1-, 2-, and 8-byte unsigned integers.
- `||` denotes byte concatenation with no separator.
- Text converted to bytes uses UTF-8.
- Lengths are measured in bytes after URL percent decoding.
- `SHA-256(x)` denotes the 32-byte SHA-256 digest of `x`.
- `HMAC-SHA256(k, x)` denotes HMAC-SHA256 with key `k` and message `x`.
- `HKDF-Extract(salt, ikm)` and `HKDF-Expand(prk, info, length)` use SHA-256 as
  specified by HKDF. Labels shown in quotation marks are their literal ASCII
  bytes and do not include a terminating zero byte.

## 3. Portal Configuration

The Portal is configured with one URL:

```text
portal://<shared-key>@<listen-host>:<listen-port>?log=<level>&tls=<mode>&crt=<path>&key=<path>&net=<mode>&spec=<spec>&alpn=<alpn>&rate=<mbps>&etar=<mbps>&dial=<ip-or-auto>&socks=<proxy>
```

Minimal configuration:

```text
portal://secret@:2077
```

The URL username is the shared key. A password component is not supported and
MUST be rejected. The listen port and a non-empty shared key are required.
Unknown query parameters are ignored.

### 3.1 Input Rules

The shared key, `spec`, and `alpn` are percent-decoded as UTF-8. A literal `+`
in `spec` or `alpn` remains `+`; it is not converted to a space. If a query key
occurs more than once, the first occurrence is used. Duplicate `socks`
parameters MUST be rejected.

| Input | Requirement | Decoded UTF-8 byte length |
| --- | --- | --- |
| Shared key | Required and non-empty | `1..255` |
| `spec` | Optional; empty is treated as omitted | `1..255` when non-empty |
| `alpn` | Optional; empty is treated as omitted | `1..255` when non-empty |
| SOCKS username | Required when SOCKS authentication is configured | `1..255` |
| SOCKS password | Required when SOCKS authentication is configured | `1..255` |

### 3.2 Parameters

| Parameter | Default | Semantics |
| --- | --- | --- |
| `log` | `info` | `none`, `debug`, `info`, `warn`, `error`, or `event`. An unknown value selects `info`. |
| `tls` | `1` | `1` creates a self-signed certificate. `2` loads PEM files from `crt` and `key`. Other values are invalid. |
| `crt` | Empty | PEM certificate chain used by `tls=2`. |
| `key` | Empty | PEM private key used by `tls=2`. |
| `net` | `mix` | Selects ingress transports. `tcp` enables TLS/TCP, `udp` enables QUIC/UDP, and `mix` enables both. Missing and empty values select `mix`; other values are invalid. |
| `spec` | `auto` | Deterministic seed for v1 authentication, padding, and frame layouts. |
| `alpn` | `now/1` | QUIC/TLS ALPN override. It does not alter any other protocol field. |
| `rate` | `0` | Client-to-target rate limit in Mbps. |
| `etar` | `0` | Target-to-client rate limit in Mbps. |
| `dial` | `auto` | Local IP literal for outbound TCP and UDP sockets. Empty, invalid, hostname, and `auto` values select the operating-system default. |
| `socks` | `none` | SOCKS5 proxy as `host:port` or `user:pass@host:port`. Missing, empty, and `none` disable proxying. |

`rate` and `etar` accept positive decimal integers. Zero, a negative value, an
invalid value, or omission disables the corresponding limit. The conversion is:

```text
bytes_per_second = mbps * 125000
```

The rate limiter is shared by all sessions handled by one Portal process. It
has independent client-to-target and target-to-client buckets.

`net` does not select the proxied traffic type. TLS/TCP supports ordinary TCP
relay and UoT. QUIC supports TCP relay on bidirectional streams and UDP relay
in DATAGRAM frames.

When `socks` is configured, every target MUST use that proxy. TCP uses SOCKS5
CONNECT. Each UDP flow uses a separate UDP ASSOCIATE and retains its control
connection for the flow lifetime. Target domain names are encoded in SOCKS5
requests and resolved by the proxy. Proxy failure MUST NOT fall back to direct
target access. `dial` binds connections and relay sockets toward the proxy.

### 3.3 Listen Address

An empty listen host binds separate IPv4 and IPv6 wildcard sockets on the same
port for each transport selected by `net`. `0.0.0.0` binds only IPv4 and `[::]`
binds only IPv6. An IP literal binds that address. A hostname is resolved and
the first resolved address is used. All selected sockets MUST bind before the
Portal begins accepting traffic.

## 4. Effective Protocol Spec

Both peers MUST build the same effective protocol spec before establishing a
session.

```text
effective_spec = decoded first `spec` value when non-empty, otherwise "auto"
effective_alpn = decoded first `alpn` value when non-empty, otherwise "now/1"
```

`effective_spec` and `effective_alpn` have independent roles. Changing `spec`
does not change ALPN. Changing `alpn` does not change authentication, padding,
or frame layout.

The shared key also does not alter the spec-derived shape. It is used only to
derive the authentication key.

### 4.1 HKDF Root

```text
spec_bytes = UTF8(effective_spec)
spec_salt  = SHA-256(spec_bytes)
spec_prk   = HKDF-Extract(spec_salt, spec_bytes)

derive(label, length) = HKDF-Expand(spec_prk, UTF8(label), length)
```

The following outputs are defined by v1:

```text
spec_id               = base64url-no-pad(derive("spec id", 8))
auth_magic            = derive("auth magic", 8)
auth_info             = derive("auth hmac info", 32)
auth_context          = derive("auth context", 32)
auth_layout_seed      = derive("auth frame layout", 8)
proxy_layout_seed     = derive("proxy frame layout", 8)
auth_padding_len_seed = derive("auth padding length", 2)
auth_padding_key      = derive("auth padding key", 32)
tcp_padding_len_seed  = derive("tcp request padding length", 1)
tcp_padding_key       = derive("tcp request padding key", 32)
```

`spec_id` is a diagnostic and conformance identifier. It is not transmitted in
a v1 protocol frame.

### 4.2 Field-Order Derivation

v1 uses a deterministic Fisher-Yates shuffle. Given an array `A`, a seed, and
an initial seed offset:

```text
for i from len(A) - 1 down to 1:
    k = initial_offset + (len(A) - 1 - i)
    j = seed[k] mod (i + 1)
    swap A[i] and A[j]
```

The three layouts are derived as follows:

| Layout | Initial array | Seed offset |
| --- | --- | --- |
| Authentication | `[magic, nonce, padding, tag]` | `0` in `auth_layout_seed` |
| TCP request | `[version, target, padding]` | `0` in `proxy_layout_seed` |
| UDP header | `[version, type, flow_id, target]` | `1` in `proxy_layout_seed` |

If the authentication shuffle produces its initial array unchanged, the result
MUST be rotated left once to `[nonce, padding, tag, magic]`. TCP and UDP layouts
do not apply this rotation.

All peers MUST implement these algorithms exactly. Derivation MUST NOT depend
on the shared key, wall-clock time, randomness, locale, platform integer width,
map iteration order, or transport-library defaults.

## 5. Transport and TLS

Nowhere v1 supports TLS 1.3 over TCP and QUIC over UDP. Both transports use the
same certificate and advertise exactly one ALPN value, `effective_alpn`.

For QUIC, the Portal:

- advertises exactly one ALPN value: `effective_alpn`;
- enables QUIC DATAGRAM;
- requires address validation with QUIC Retry before accepting a connection;
- uses BBR congestion control;
- initially advertises one bidirectional stream and 64 KiB connection-level
  receive credit;
- after authentication, raises the bidirectional-stream limit to
  `NOW_QUIC_MAX_STREAMS` and the connection-level receive credit to 32 MiB;
- advertises 16 MiB per-stream receive credit;
- permits up to 32 MiB of unacknowledged stream data per connection;
- does not accept unidirectional streams;
- uses `NOW_UDP_IDLE_TIMEOUT` as the QUIC idle timeout; and
- does not send transport-level keepalive packets.

The Portal explicitly disables TLS 1.3 early data and half-RTT server data for
both QUIC and TLS/TCP. Application data is therefore never accepted as 0-RTT.

A QUIC client MUST offer exactly one ALPN value equal to `effective_alpn`,
enable QUIC DATAGRAM, and support bidirectional streams. A TCP client MUST
negotiate TLS 1.3 with the same ALPN. An ALPN mismatch is a
connection-establishment failure. Plaintext TCP is not supported.

### 5.1 TLS Modes

`tls=1` generates a new self-signed certificate for `localhost` when the Portal
starts. Client trust for this mode is an application decision and MUST be
explicit.

`tls=2` loads a PEM certificate chain from `crt` and a PEM private key from
`key`. Both files must be valid when the Portal starts. On a ClientHello, the
Portal reloads them if `NOW_RELOAD_INTERVAL` has elapsed. A successful reload
replaces the cached certificate. A failed reload is logged and the previous
certificate remains active.

Clients using `tls=2` SHOULD apply normal platform certificate and server-name
verification. TLS trust policy and SNI do not change the v1 wire format.

## 6. Connection Lifecycle

After the QUIC handshake:

1. The client opens the first bidirectional stream as the authentication
   stream.
2. The client writes exactly one v1 authentication frame and finishes its send
   side.
3. After successful authentication, each additional bidirectional stream may
   carry one TCP relay.
4. UDP relay traffic may use QUIC DATAGRAM frames for the lifetime of the
   authenticated connection.

The Portal samples one absolute authentication deadline after the QUIC or TLS
handshake completes. The deadline is `NOW_HANDSHAKE_TIMEOUT` multiplied by a
system-random factor in `[0.8, 1.2]`; if randomness is unavailable, the
configured timeout is used unchanged. For QUIC, waiting for the authentication
stream and reading its complete frame share this single deadline. No target
traffic is forwarded before authentication succeeds.

QUIC DATAGRAM frames that arrive before authentication are actively drained.
The Portal retains at most 64 KiB in aggregate and delivers those retained
frames to the session after successful authentication. Excess frames and all
retained frames from a failed authentication are discarded.

For TLS/TCP, each proxy flow uses a new connection:

1. The client completes TLS 1.3.
2. The client sends exactly one v1 authentication frame.
3. The client sends one v1 TCP request frame immediately or after keeping the
   authenticated connection idle in a client-side warm pool.
4. A normal target selects TCP relay and all remaining bytes are raw
   client-to-target TCP payload. The reserved target
   `uot.nowhere.invalid:0` selects UoT and the client continues with the setup
   and packet frames defined in Section 9.2.

There is no authentication response, post-relay connection reuse, or
multiplexing on the TCP transport. A pooled connection is consumed by its first
request and carries exactly one TCP relay or one UoT flow. Each accepted TCP
connection is stateless with respect to every other connection. The Portal
closes an authenticated connection that does not send its request frame within
40 seconds.

The reference client starts one warm connection on a cold pool. Consuming a
warm connection starts up to two replacements without allowing idle plus
in-progress connections to exceed the configured pool limit. Each unconsumed
slot expires 30 seconds after it is created; expiration does not trigger a
replacement.

## 7. Authentication

The credential key is:

```text
auth_key = SHA-256(shared_key_bytes)
```

The client supplies a 32-byte nonce. It SHOULD generate a fresh,
cryptographically random nonce for each connection.

### 7.1 Padding and Tag

```text
auth_padding_len = 1 + (u16be(auth_padding_len_seed) mod 255)

auth_padding = HKDF-Expand(
    auth_padding_key,
    UTF8("auth padding bytes") || nonce || u8(auth_padding_len),
    auth_padding_len
)

auth_tag = HMAC-SHA256(
    auth_key,
    auth_info || auth_context || nonce ||
    u8(auth_padding_len) || auth_padding
)
```

`auth_padding_len` is in the range `1..255`.

### 7.2 Frame

The authentication frame contains these four elements in the derived
authentication order:

| Element | Encoding |
| --- | --- |
| `magic` | `auth_magic` (8 bytes) |
| `nonce` | 32 bytes |
| `padding` | `auth_padding_len_u8 || auth_padding` |
| `tag` | `auth_tag` (32 bytes) |

The complete frame length is `74..328` bytes. The receiver MUST verify the
frame length, magic, declared padding length, deterministic padding bytes, and
HMAC tag. It MUST also require end-of-stream immediately after the frame. Tag
and padding comparisons SHOULD be constant-time.

Correct authentication proceeds immediately. A missing stream, truncated
frame, EOF, missing FIN, trailing bytes, or invalid field, padding, or HMAC is
held until the sampled absolute deadline. The reference Portal then closes
QUIC with application code `0x01` and reason `access denied`, or closes TCP
without an application response. Network closure is initiated before detailed
failure information is written to the Portal's local log. Service shutdown
cancels the delay.

The Portal applies a process-wide pre-authentication admission limit shared by
TCP and QUIC: at most 256 connections in total and 32 per IPv4 `/32` or IPv6
`/64`. A validated QUIC attempt above either limit is silently ignored; an
accepted TCP connection above either limit is immediately closed. A slot is
released as soon as authentication succeeds or fails.

## 8. TCP Relay

Each TCP relay uses either one new bidirectional QUIC stream or one dedicated
TLS/TCP connection. In both cases the client writes the same request frame,
followed immediately by raw client-to-target TCP bytes.

### 8.1 Request Padding

```text
tcp_padding_len = tcp_padding_len_seed[0] mod 64

tcp_padding = HKDF-Expand(
    tcp_padding_key,
    UTF8("tcp request padding bytes") || target_utf8 ||
    u8(tcp_padding_len),
    tcp_padding_len
)
```

`tcp_padding_len` is in the range `0..63`. Its bytes are deterministic for the
pair `(effective_spec, target)`.

### 8.2 Request Frame

The request frame contains these three elements in the derived TCP order:

| Element | Encoding |
| --- | --- |
| `version` | `u8(1)` |
| `target` | `target_len_u16 || target_utf8` |
| `padding` | `tcp_padding_len_u8 || tcp_padding` |

The receiver MUST reject a version other than `1`, an invalid target, an
incorrect padding length, or incorrect padding bytes. The request padding is
not forwarded to the target.

After parsing the request, the Portal either resolves and connects directly to
the target or sends the target unchanged in a configured SOCKS5 CONNECT
request. `dial` binds the direct target socket or the connection to the SOCKS5
server. The Portal then relays bytes in both directions. When one direction
reaches EOF, the other direction may continue for at most
`NOW_TCP_READ_TIMEOUT`.

## 9. UDP Relay

UDP relay has two transport-specific forms:

- QUIC DATAGRAM multiplexes flows by `(flow_id, target)` on one authenticated
  QUIC connection.
- UoT carries one target flow as length-prefixed packets on one authenticated
  TLS/TCP connection.

The forms share target validation, outbound UDP dialing, rate limits, idle
timeouts, and UDP counters. Their wire frames are otherwise independent.

### 9.1 QUIC DATAGRAM Header

Each QUIC DATAGRAM contains a derived-order header followed by an opaque
payload.

| Element | Encoding |
| --- | --- |
| `version` | `u8(1)` |
| `type` | One of the values below |
| `flow_id` | `u64` scoped to the authenticated QUIC connection |
| `target` | `target_len_u16 || target_utf8` |

The header elements appear in the derived UDP order. The payload always follows
the complete header and is never shuffled.

| Type | Value | Direction and meaning |
| --- | --- | --- |
| Request | `1` | Client to Portal; open or reuse the flow and forward the payload to the target. |
| Response | `2` | Portal to client; payload received from the target. |
| Close | `3` | Client to Portal; close the matching flow. Any payload is ignored. |

A UDP flow is identified by `(flow_id, target)` within one QUIC connection.
Different targets with the same flow ID are distinct flows. The response uses
the request's flow ID and target. The Portal closes an inactive flow after
`NOW_UDP_IDLE_TIMEOUT`.

Malformed datagrams, unsupported versions, unknown types, and response frames
received by the Portal are not forwarded. A close frame for an unknown flow has
no effect.

### 9.2 UDP-over-TCP (UoT)

UoT is available only on an authenticated TLS/TCP connection. It is selected
by sending the ordinary spec-derived TCP request frame from Section 8 with this
reserved target:

```text
uot.nowhere.invalid:0
```

The reserved target is a protocol switch and MUST NOT be treated as a TCP
destination. Its request frame uses the same derived field order and
deterministic padding as every other TCP request.

Immediately after that request, the client MUST send exactly one setup frame:

```text
target_len_u16 || target_utf8
```

`target_len_u16` MUST be from 1 through 512, and `target_utf8` MUST satisfy
Section 10. The Portal bounds reading the complete setup target by
`NOW_HANDSHAKE_TIMEOUT`. It then resolves the target and opens one connected UDP
socket, optionally binding its source address according to `dial`. With SOCKS5
enabled, it instead creates a per-flow UDP ASSOCIATE, keeps the associated TCP
control connection open, and sends the target in each SOCKS5 UDP packet.

After setup, both directions consist only of packet frames:

```text
payload_len_u16 || payload
```

`payload_len_u16` is from 0 through 65535. Each frame represents exactly one UDP
packet, so implementations MUST preserve frame and packet boundaries. UoT has
no flow ID, message type, or in-band close frame. One TLS/TCP connection carries
one target flow; clients use separate connections for different concurrent
targets.

Traffic in either direction refreshes `NOW_UDP_IDLE_TIMEOUT`. Clean TCP EOF,
truncated or invalid framing, a target socket error, the idle timeout, or
service shutdown closes the UoT flow. Payload bytes are charged to `rate` and
`etar` and recorded in the UDP counters. The two-byte packet lengths, setup
frame, authentication frame, and request frame are not counted as UDP payload.

## 10. Target Encoding

TCP requests, QUIC DATAGRAM headers, and UoT setup frames use the same target
representation. `target_utf8` MUST:

- be valid UTF-8;
- have a byte length in `1..512`;
- contain a non-empty port component; and
- use brackets around an IPv6 literal, for example `[2001:db8::1]:443`.

An unbracketed target may contain only the single colon that separates host and
port. v1 codec validation does not require the host component to be non-empty
and does not parse the port as an integer; target resolution and dialing may
still fail after the frame is accepted.

## 11. Rate Limiting and Counters

The Portal applies one process-wide limiter with two independent directions:

- `rate`: client-to-target TCP bytes and QUIC DATAGRAM/UoT UDP payload bytes;
- `etar`: target-to-client TCP bytes and QUIC DATAGRAM/UoT UDP payload bytes.

Rate limits do not select or modify QUIC congestion control. BBR remains fixed.

At startup and then every `NOW_REPORT_INTERVAL`, the Portal emits this event
record when the active log level includes events:

```text
CHECK_POINT|MODE=0|PING=0ms|POOL=<n>|TCPS=<n>|UDPS=<n>|TCPRX=<bytes>|TCPTX=<bytes>|UDPRX=<bytes>|UDPTX=<bytes>
```

| Field | Meaning |
| --- | --- |
| `TCPS` | Active TCP relay streams. |
| `UDPS` | Active QUIC DATAGRAM and UoT flows. |
| `TCPRX` | Client-to-target TCP bytes. |
| `TCPTX` | Target-to-client TCP bytes. |
| `UDPRX` | Client-to-target UDP payload bytes. |
| `UDPTX` | Target-to-client UDP payload bytes. |

`POOL` is the number of authenticated TLS/TCP connections waiting for their
first request frame. TLS handshakes, authentication in progress, active TCP or
UoT relays, and QUIC connections are not included. `MODE` and `PING` remain
fixed to the values shown in v1.

`NOW_REPORT_INTERVAL` controls only this local telemetry schedule. It does not
control QUIC keepalive traffic.

## 12. Runtime Controls

These environment variables control the reference Portal. They do not alter
the v1 derivation or frame formats.

| Variable | Default | Purpose |
| --- | --- | --- |
| `NOW_QUIC_MAX_STREAMS` | `1024` | Maximum concurrent QUIC bidirectional streams. |
| `NOW_TCP_DATA_BUF_SIZE` | `32768` | Buffer size for each TCP relay direction. |
| `NOW_UDP_DATA_BUF_SIZE` | `65536` | UDP target-socket receive buffer size. |
| `NOW_TCP_DIAL_TIMEOUT` | `15s` | TCP target connection timeout. |
| `NOW_UDP_DIAL_TIMEOUT` | `15s` | UDP target connection timeout. |
| `NOW_TCP_READ_TIMEOUT` | `30s` | Grace period after one TCP direction finishes. |
| `NOW_UDP_IDLE_TIMEOUT` | `120s` | QUIC idle timeout and QUIC DATAGRAM/UoT flow idle timeout. |
| `NOW_HANDSHAKE_TIMEOUT` | `5s` | Base for the single jittered authentication deadline. |
| `NOW_REPORT_INTERVAL` | `5s` | Local event interval. |
| `NOW_SHUTDOWN_TIMEOUT` | `5s` | Endpoint idle wait during shutdown. |
| `NOW_RELOAD_INTERVAL` | `3600s` | Minimum interval between PEM reload attempts. |

Duration values accept human-readable forms supported by the Portal, such as
`500ms`, `15s`, or `2m`. Invalid values use the listed defaults. Integer values
must be non-negative; invalid or negative values use the listed defaults.

## 13. Interoperability Requirements

Two peers interoperate only when they use the same:

- shared key;
- `effective_spec` and v1 derivation rules;
- `effective_alpn`; and
- frame version `1`.

An ALPN mismatch fails during TLS or QUIC negotiation. With equal ALPN but a
different shared key or effective spec, authentication fails before proxy
traffic is processed.

A conforming implementation MUST reject malformed or truncated frames, invalid
field lengths, unsupported versions, incorrect deterministic padding, invalid
authentication tags, trailing authentication-stream bytes, and invalid UoT
setup or packet frames. It MUST bound all allocations using the limits in this
document.

The v1 derivation, labels, field-order algorithm, integer encodings, and frame
type values are protocol constants. Changing any of them is not compatible with
Nowhere v1.

## 14. Conformance

An implementation should verify at least the following cases:

1. Omitted, empty, and explicit `spec=auto` produce identical effective specs.
2. Omitted and empty `alpn` select `now/1`.
3. An explicit ALPN changes only `effective_alpn`.
4. Inputs at 255 decoded bytes are accepted and inputs at 256 bytes are
   rejected.
5. Different shared keys with the same spec produce the same derived layout but
   different authentication tags.
6. Different specs produce their own authentication constants, padding, and
   layouts.
7. Authentication, TCP request, UDP datagram, UoT setup, and UoT packet
   encoders round-trip through their decoders.
8. Wrong versions, target lengths, padding lengths, padding bytes, frame types,
   and tags are rejected.
9. The authentication stream is rejected if any byte follows the valid frame.
10. A TLS/TCP request for `uot.nowhere.invalid:0` switches to UoT, preserves UDP
    packet boundaries in both directions, and records the flow as UDP.

For the following fixed inputs:

```text
shared key = "secret"
spec       = "auto"
ALPN       = "now/1"
nonce      = 32 bytes, each equal to 0x07
TCP target = "example.com:443"
```

the hexadecimal encoding of the authentication frame is:

```text
33e07eceb833c31f41bea81b0c57a48d0745d1fc22df836733e99316d7ead83e
d065c573fe8427ef058b0eb2d90a070707070707070707070707070707070707
0707070707070707070707070707
```

and the hexadecimal encoding of the TCP request frame is:

```text
000f6578616d706c652e636f6d3a343433013c1526b9b947228779cfc539fe46
81bcb5d1e20efa2bcb9f89eda5b473625c3c6b7fb12499fd33edfefb1934c9a
e0bfc0e849f4c94814f4f2f9ae782e8
```

Whitespace and line breaks in these hexadecimal displays are not part of the
frames.
