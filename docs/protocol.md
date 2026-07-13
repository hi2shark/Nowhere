# Nowhere Protocol v1

## 1. Status and Scope

This document defines version 1 of the Nowhere proxy protocol and the Portal
configuration required by the reference implementation.

Nowhere carries authenticated TCP and UDP proxy traffic over TLS/TCP or QUIC.
TCP uses a dedicated TLS/TCP connection or a QUIC bidirectional stream. UDP
uses fragmentable QUIC DATAGRAM frames or a typed UDP-over-TCP (UoT) flow. A shared
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

The two layouts are derived as follows:

| Layout | Initial array | Seed offset |
| --- | --- | --- |
| Authentication | `[magic, nonce, padding, tag]` | `0` in `auth_layout_seed` |
| TCP request | `[version, target, padding]` | `0` in `proxy_layout_seed` |

If the authentication shuffle produces its initial array unchanged, the result
MUST be rotated left once to `[nonce, padding, tag, magic]`. The TCP layout does
not apply this rotation. UDP frames use the fixed format in Section 9.1 and are
not spec-derived.

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
3. The authentication frame binds the connection to a client-generated
   128-bit logical session ID.
4. After successful authentication, each additional bidirectional stream may
   carry one TCP data lane or one UDP setup/control lane for a logical flow.
5. UDP relay traffic may use QUIC DATAGRAM frames for the lifetime of the
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
3. The client sends one logical-flow header immediately or after keeping the
   authenticated connection idle in a client-side warm pool.
4. `FLOW_OPEN` and `FLOW_DUPLEX` are followed by the ordinary target request.
   `FLOW_ATTACH` is header-only.
5. A TCP flow continues with raw stream bytes. A UDP flow continues with the
   typed UoT frames defined in Section 9.2.

There is no authentication response, post-relay connection reuse, or
multiplexing on the TCP transport. A pooled connection is consumed by its first
request and carries exactly one TCP relay or one UoT flow half. Connections
sharing an authenticated session ID may contribute carrier halves to multiple
asymmetric flows distinguished by `flow_id`. The Portal never
associates them by source IP, so TCP and QUIC may arrive through different
interfaces or NAT mappings. An authenticated connection that sends no request
frame is closed after 40 seconds.

For a `tcp/tcp` client with TLS preconnection enabled, the reference client
starts one warm connection on a cold pool. Consuming a warm connection starts up to two
replacements without allowing idle plus in-progress connections to exceed the
configured pool limit. Each unconsumed slot expires 30 seconds after it is
created; expiration does not trigger a replacement. A client pool value of `0`
disables this warm pool and opens TLS/TCP lanes on demand. Any carrier matrix
containing UDP disables the warm pool; both QUIC and TLS/TCP halves are then
created lazily.

## 7. Authentication

The credential key is:

```text
auth_key = SHA-256(shared_key_bytes)
```

The client supplies a 32-byte nonce and a 16-byte random `session_id`. It SHOULD
generate a fresh, cryptographically random nonce for each connection and one
session ID for each transport bundle; every QUIC session and TLS/TCP lane in
that bundle carries the same session ID.

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
    u8(auth_padding_len) || auth_padding || session_id
)
```

`auth_padding_len` is in the range `1..255`.

### 7.2 Frame

The authentication frame contains four elements in the derived authentication
order followed by the fixed session ID:

| Element | Encoding |
| --- | --- |
| `magic` | `auth_magic` (8 bytes) |
| `nonce` | 32 bytes |
| `padding` | `auth_padding_len_u8 || auth_padding` |
| `tag` | `auth_tag` (32 bytes) |
| `session_id` | 16 bytes, appended after the shuffled elements |

The complete frame length is `90..344` bytes. The receiver MUST verify the
frame length, magic, declared padding length, deterministic padding bytes, and
HMAC tag. A QUIC authentication stream MUST end immediately after the frame. A
TLS/TCP lane reads exactly the authentication frame length and treats following
bytes as its request frame. Tag and padding comparisons SHOULD be constant-time.

Correct authentication proceeds immediately. A missing stream, truncated
frame, EOF, missing FIN, trailing bytes, or invalid field, padding, or HMAC is
held until the sampled absolute deadline. The reference Portal then closes
QUIC with application code `0x01` and reason `access denied`, or closes TCP
without an application response. Network closure is initiated before detailed
failure information is written to the Portal's local log. Service shutdown
cancels the delay.

If a newly authenticated QUIC connection presents the `session_id` of an
older active QUIC connection, the Portal replaces the older carrier. This
permits recovery from a client-side path failure while the stale server-side
connection is still waiting for its idle timeout. Existing flows on the older
carrier are not migrated.

The Portal applies a process-wide pre-authentication admission limit shared by
TCP and QUIC: at most 256 connections in total and 32 per IPv4 `/32` or IPv6
`/64`. A validated QUIC attempt above either limit is silently ignored; an
accepted TCP connection above either limit is immediately closed. A slot is
released as soon as authentication succeeds or fails.

## 8. TCP Relay

Each TCP relay uses either one new bidirectional QUIC stream or one dedicated
TLS/TCP connection. In both cases the client writes the common logical-flow
header and, when required by its role, the same target request frame. Raw TCP
payload follows on the uplink half.

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

### 8.3 Logical Flow Envelope

Every TCP and UDP logical flow begins with this fixed 14-byte envelope:

```text
magic_f1 || version_u8(1) || role_u8 || flow_id_u64 ||
kind_u8 || uplink_u8 || downlink_u8
```

| Field | Value |
| --- | --- |
| `magic_f1` | `0xf1` |
| `version` | `1` |
| `role` | `1` = `FLOW_OPEN`, `2` = `FLOW_ATTACH`, `3` = `FLOW_DUPLEX` |
| `kind` | `1` = TCP, `2` = UDP |
| `uplink`, `downlink` | `1` = TLS/TCP, `2` = QUIC/UDP |

`flow_id` MUST be nonzero and is unique within the authenticated logical
session across both TCP and UDP. `FLOW_DUPLEX` requires equal carriers and is
used for a symmetric flow. `FLOW_OPEN` and `FLOW_ATTACH` require different
carriers and form the uplink and downlink halves of an asymmetric flow.

`FLOW_OPEN` and `FLOW_DUPLEX` are followed by the target request from Section
8.2. `FLOW_ATTACH` is followed by no target. The Portal keys ownership and
pending halves by `(session_id, flow_id)`, requires identical kind and carrier
metadata, and dials the target only after the complete logical flow exists.
The receiver MUST NOT guess a legacy data plane from payload bytes; a flow
without this envelope is invalid.

The selected downlink returns a setup result before application downlink data:

```text
magic_f2(0xf2) || version_u8(1) || status_u8 || code_u8
```

`status=1` means `READY` and requires `code=0`. `status=2` means `REJECT` and
uses code `1` through `7` for `INVALID_REQUEST`, `METADATA_CONFLICT`,
`PAIR_TIMEOUT`, `FLOW_LIMIT`, `DIAL_FAILED`, `SESSION_REPLACED`, and
`INTERNAL_ERROR`, respectively. TCP flows use this four-byte result on both
carriers. UDP over TLS/TCP uses the equivalent typed UoT result from Section
9.2. An asymmetric uplink does not receive a separate result; the client MUST
wait for its selected downlink before exposing the combined logical flow.

## 9. UDP Relay

UDP relay has two transport-specific forms:

- QUIC DATAGRAM multiplexes flows by `flow_id` on one authenticated QUIC
  connection and fragments packets that exceed the current DATAGRAM limit.
- UoT carries one logical-flow half, or one symmetric Duplex flow, as typed
  packet frames on one authenticated TLS/TCP connection.

The forms share target validation, outbound UDP dialing, rate limits, idle
timeouts, and UDP counters. Their wire frames are otherwise independent.

### 9.1 QUIC DATAGRAM Frames

Every QUIC UDP frame begins with this fixed base header:

```text
magic[4]("NOWU") || type_u8 || flow_id_u64
```

| Type | Value | Body |
| --- | --- | --- |
| `DATA` | `1` | `fragment_header || fragment` |
| `CLOSE` | `2` | Empty |

The fragment header is:

```text
packet_id_u32 || fragment_id_u8 || fragment_count_u8 || total_len_u16
```

`fragment_id` is zero-based and less than `fragment_count`, which is from 1
through 255. `total_len` is the original UDP payload length from 0 through
65535. A zero-length UDP packet is encoded as exactly one fragment with
`fragment_id=0`, `fragment_count=1`, `total_len=0`, and no fragment bytes.

The sender MUST split a packet so every encoded frame fits the connection's
current maximum QUIC DATAGRAM size. All fragments of a packet use the same
nonzero packet ID, count, and total length. The receiver reassembles the
complete UDP packet before writing one datagram to the target or delivering one
datagram to the client. Partial packets are bounded by the connection byte
budget, a 64-slot cap, and a 10-second lifetime.

QUIC DATAGRAM never opens a flow and never carries a target. Before DATA, the
client opens a reliable bidirectional control stream containing the logical
flow header and any role-required target request, then finishes its send side.
The selected downlink receives the four-byte flow result on that control
stream. After `READY`, the control stream is no longer part of the data plane;
DATA and CLOSE use DATAGRAM only. DATA for an unknown flow is ignored; it is
never interpreted as setup and never blocks the receive loop on a response
DATAGRAM.

The Portal uses backpressured DATAGRAM submission so a newer frame cannot
silently evict an older unsent frame from the local QUIC queue. If the path MTU
shrinks while a packet is being submitted, the sender recomputes fragments and
retries once. A packet that still cannot be submitted is dropped without
closing the UDP flow; later packets remain eligible for delivery.

A UDP flow is identified by `flow_id` within one authenticated QUIC connection.
The Portal closes an inactive flow after `NOW_UDP_IDLE_TIMEOUT`.

The reference Portal dispatches each flow independently. Target dialing,
rate-limit waits, and target socket I/O for one flow do not block DATAGRAM
dispatch to other flows. Each flow queues at most 64 client datagrams. New
requests are dropped when that queue or the per-QUIC-connection queued-byte
budget is full; already accepted requests remain FIFO. New UDP flow setup is
rejected when the authenticated logical session's shared flow limit is full.

Malformed frames, invalid fragment metadata, conflicting duplicate fragments,
and unknown types are not forwarded. The former derived-order UDP format and
the earlier compact `0x11..0x14` format are not accepted.

### 9.2 UDP-over-TCP (UoT)

UoT is available only on an authenticated TLS/TCP connection. The common
logical-flow header selects UDP with `kind=2`; `FLOW_OPEN` and `FLOW_DUPLEX` are
then followed by the ordinary target request from Section 8.2, while
`FLOW_ATTACH` remains header-only. There is no reserved target or second setup
target.

After a complete logical flow exists, the Portal resolves the target and opens
one connected UDP socket, optionally binding its source address according to
`dial`. With SOCKS5 enabled, it instead creates a per-flow UDP ASSOCIATE, keeps
the associated TCP control connection open, and sends the target in each
SOCKS5 UDP packet.

After setup, both directions consist only of typed frames:

```text
kind_u8 || payload_len_u16 || payload
```

| Kind | Value | Meaning |
| --- | --- | --- |
| `DATA` | `1` | One complete UDP packet; an empty payload is valid. |
| `READY` | `2` | Empty setup success on the selected downlink. |
| `CLOSE` | `3` | An empty explicit close notification. |
| `REJECT` | `4` | Exactly one flow error-code byte from Section 8.3. |

`payload_len_u16` is from 0 through 65535. `READY` and `CLOSE` MUST have zero
length; `REJECT` MUST have length one. Each `DATA` frame represents exactly one
UDP packet, so implementations MUST preserve frame and packet boundaries. One
TLS/TCP connection carries one logical-flow half; clients use separate
connections for different concurrent targets.

Traffic in either direction refreshes `NOW_UDP_IDLE_TIMEOUT`. Clean TCP EOF,
truncated or invalid framing, a target socket error, the idle timeout, or
service shutdown closes the UoT flow. Payload bytes are charged to `rate` and
`etar` and recorded in the UDP counters. The flow header, target request,
typed-frame headers, and authentication frame are not counted as UDP payload.

## 10. Target Encoding

The target request following `FLOW_OPEN` or `FLOW_DUPLEX` uses one common target
representation for every kind and carrier. `target_utf8` MUST:

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
UoT relays, and QUIC connections are not included. `MODE` is `0` for `net=mix`,
`1` for `net=tcp`, and `2` for `net=udp`. `PING` remains fixed to the value
shown in v1.

`NOW_REPORT_INTERVAL` controls only this local telemetry schedule. It does not
control QUIC keepalive traffic.

At debug log level, the Portal also emits carrier-level absolute counters
without changing `CHECK_POINT`:

```text
LINK_STATUS|TCP=<lanes>|UDP=<sessions>|PAIRS=<sessions>|UPTCP=<payload-bytes>|UPUDP=<payload-bytes>|DOWNTCP=<payload-bytes>|DOWNUDP=<payload-bytes>
```

## 12. Runtime Controls

These environment variables control the reference Portal. They do not alter
the v1 derivation or frame formats.

| Variable | Default | Purpose |
| --- | --- | --- |
| `NOW_QUIC_MAX_STREAMS` | `1024` | Maximum concurrent QUIC bidirectional streams. |
| `NOW_QUIC_MAX_UDP_FLOWS` | `256` | Maximum active UDP flows per authenticated logical session, across QUIC DATAGRAM, UoT, and asymmetric carrier combinations. |
| `NOW_QUIC_UDP_QUEUE_BYTES` | `4194304` | Maximum queued and partially reassembled UDP payload bytes per authenticated QUIC connection. |
| `NOW_TCP_IDLE_POOL_CONNS` | `4096` | Maximum authenticated TLS/TCP connections waiting for a first request. |
| `NOW_MAX_PENDING_PAIRS` | `1024` | Maximum pending logical-flow records (`flow_id` values) per session. |
| `NOW_FLOW_PAIR_TIMEOUT` | `15s` | Time allowed to complete a split logical flow. |
| `NOW_TCP_DATA_BUF_SIZE` | `32768` | Buffer size for each TCP relay direction. |
| `NOW_UDP_DATA_BUF_SIZE` | `65536` | UDP target-socket receive buffer size. |
| `NOW_TCP_DIAL_TIMEOUT` | `15s` | TCP target connection timeout. |
| `NOW_UDP_DIAL_TIMEOUT` | `15s` | UDP target connection timeout. |
| `NOW_TCP_READ_TIMEOUT` | `30s` | Grace period after one TCP direction finishes. |
| `NOW_UDP_IDLE_TIMEOUT` | `120s` | QUIC idle timeout and QUIC DATAGRAM/UoT flow idle timeout. |
| `NOW_HANDSHAKE_TIMEOUT` | `5s` | Base for the single jittered authentication deadline. |
| `NOW_REPORT_INTERVAL` | `5s` | Local event interval. |
| `NOW_SHUTDOWN_TIMEOUT` | `5s` | Single graceful drain window shared by endpoints, accept loops, and flow tasks. |
| `NOW_RELOAD_INTERVAL` | `3600s` | Minimum interval between PEM reload attempts. |

Duration values accept human-readable forms supported by the Portal, such as
`500ms`, `15s`, or `2m`. Invalid values use the listed defaults.
`NOW_QUIC_MAX_UDP_FLOWS`, `NOW_QUIC_UDP_QUEUE_BYTES`, and
`NOW_TCP_IDLE_POOL_CONNS` must be positive; zero or invalid values use
their defaults and emit a warning. Other integer values must be non-negative;
invalid or negative values use the listed defaults.

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
authentication tags, trailing authentication-stream bytes, and invalid flow or
UoT packet frames. It MUST bound all allocations using the limits in this
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
7. Authentication, flow header/result, TCP request, fixed UDP fragment, and
   typed UoT encoders round-trip through their decoders.
8. Wrong versions, target lengths, padding lengths, padding bytes, frame types,
   and tags are rejected.
9. The authentication stream is rejected if any byte follows the valid frame.
10. A TLS/TCP logical flow with `kind=UDP` uses typed UoT, preserves UDP packet
    boundaries in both directions, and records the flow as UDP.

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
