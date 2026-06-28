# Security Notes

Nowhere v1 is intentionally small, but it is still an exposed network service.
This document summarizes the security properties and operator choices that are
outside the wire format.

## Supported Transport Security

The Portal supports only TLS-backed modes:

| Mode | Behavior |
| --- | --- |
| `tls=1` | Generate an in-memory self-signed certificate at startup. |
| `tls=2` | Load a PEM certificate chain and private key from `crt` and `key`. |

Plaintext `tls=0` is rejected.

TLS 1.3 early data and half-RTT server data are disabled for both TLS/TCP and
QUIC. Application data is not accepted as 0-RTT.

TLS/TCP carries ordinary TCP relays and UoT UDP flows. QUIC carries TCP relays
on bidirectional streams and UDP flows in DATAGRAM frames. UoT setup and packet
frames are accepted only after the same TLS/TCP authentication used by ordinary
TCP relays.

## Shared Key

The shared key is the URL username after percent decoding. It must be non-empty
and at most 255 UTF-8 bytes.

Use a high-entropy value. Do not reuse a human password from another system. Do
not put production keys in shell history, process managers that expose command
lines broadly, issue trackers, examples, or repository files.

The protocol derives:

```text
auth_key = SHA-256(shared_key_bytes)
```

The shared key does not alter the spec-derived field order or padding layout.
It only changes authentication tags.

## Spec and ALPN Agreement

Both peers must agree on:

- shared key;
- `effective_spec`;
- `effective_alpn`; and
- frame version `1`.

`spec` changes the authentication constants, padding, and field order. `alpn`
changes TLS and QUIC negotiation only. A mismatch in ALPN fails during transport
setup. A mismatch in shared key or spec fails during authentication.

## Authentication Failure Behavior

No target traffic is forwarded before authentication succeeds. Failed
authentication paths are delayed until one sampled absolute deadline:

```text
NOW_HANDSHAKE_TIMEOUT * [0.8, 1.2]
```

After the delay, TCP closes without an application response. QUIC closes with
application code `0x01` and reason `access denied`. Detailed failure
information is written only to the local log and only after network closure is
initiated.

## Pre-Authentication Resource Limits

The Portal limits unauthenticated work before accepting a client:

- QUIC Retry is required before a QUIC connection reaches authentication.
- At most 256 pre-authenticated connections are admitted process-wide.
- At most 32 pre-authenticated connections are admitted per IPv4 `/32` or IPv6
  `/64`.
- QUIC DATAGRAM frames received before authentication are drained with a 64 KiB
  aggregate retention budget.

These limits reduce unauthenticated resource pressure. They are not a
replacement for network-level filtering or service supervision.

## TLS Trust Policy

For `tls=1`, clients must explicitly trust or pin the generated certificate.
The generated certificate is not stable across restarts.

For `tls=2`, clients should use normal platform certificate validation and
server-name checks unless they deliberately deploy a different trust model.
Fingerprint pinning can be useful in controlled deployments, but it must be
rotated deliberately when certificates change.

## Deployment Guidance

- Use `tls=2` for public or long-lived deployments.
- Keep certificate and key files readable only by the service user.
- Place the Portal behind firewall rules that match the intended client set
  when possible.
- Prefer explicit `net=tcp` or `net=udp` when one ingress transport is not
  needed. `net=tcp` still permits UDP through UoT.
- Monitor `CHECK_POINT` counters and process restarts.
- Rotate shared keys through a coordinated client and server rollout.
- Treat debug logs as sensitive because they may expose operational details.
- Treat management-layer state, API responses, event streams, and logs as
  sensitive when they contain a Portal URL: its username is the shared key.

## Non-Goals

The Portal does not provide:

- user accounts;
- key rotation protocol messages;
- remote management APIs;
- application-layer authorization rules;
- target allowlists; or
- plaintext transport.

Implement those controls outside the Portal when a deployment requires them.
[OpenCtrl](https://github.com/NodePassProject/OpenCtrl) is a supported external
management layer; see the [integration guide](integrations.md) for its security
and process-lifecycle boundaries.
