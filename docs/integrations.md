# Integrations

Nowhere keeps protocol service inside the Portal and composes with external
management and client software. These integrations are optional: the Portal
remains usable as a standalone foreground process, and compatible clients can
implement the [protocol specification](protocol.md) directly.

## OpenCtrl Management

[OpenCtrl](https://github.com/NodePassProject/OpenCtrl) is a supported control
plane for URL-defined runtime processes. Its process contract matches Nowhere:
the managed binary receives one configuration URL, stays in the foreground,
and reports logs and metrics through standard output.

OpenCtrl adds durable instance definitions, lifecycle operations, a versioned
REST API, Server-Sent Events, and checkpoint-derived counters. It does not
change the Portal configuration or wire protocol.

### Start the Control Plane

Build or install both binaries, then point OpenCtrl at the Nowhere executable:

```sh
openctrl 'master://127.0.0.1:8080?bin=/usr/local/bin/nowhere'
```

On first start, OpenCtrl prints an API key. Use the reported value for protected
API requests:

```sh
BASE='http://127.0.0.1:8080/api/v2'
API_KEY='<openctrl-api-key>'
```

For a network-accessible control plane, configure OpenCtrl TLS and restrict
access according to its own documentation.

### Create a Portal

Create an instance by passing the complete Portal URL as the instance `url`:

```sh
curl -X POST "${BASE}/instances" \
  -H "X-API-Key: ${API_KEY}" \
  -H 'Content-Type: application/json' \
  -d '{"alias":"edge-a","url":"portal://change-me@:2077?spec=nightfall"}'
```

OpenCtrl starts the child asynchronously. The create response can therefore
show `stopped` before the process reaches `running`. Save the returned `id`,
then read the instance or subscribe to events for the live state:

```sh
INSTANCE_ID='<instance-id>'

curl -H "X-API-Key: ${API_KEY}" \
  "${BASE}/instances/${INSTANCE_ID}"

curl -N -H "X-API-Key: ${API_KEY}" \
  "${BASE}/events"
```

The example intentionally omits `log`. Nowhere's default `info` level retains
ordinary operational logs and emits EVENT checkpoints.

For a long-lived Portal, use a stable certificate and an explicit public
configuration:

```text
portal://change-me@:2077?tls=2&crt=/etc/nowhere/cert.pem&key=/etc/nowhere/key.pem&net=mix&spec=nightfall&alpn=now%2F1
```

Certificate and private-key paths are resolved by the Nowhere child process
and must be readable by the operating-system user running OpenCtrl.

### Lifecycle Operations

OpenCtrl accepts lifecycle actions through `PATCH`:

```sh
curl -X PATCH "${BASE}/instances/${INSTANCE_ID}" \
  -H "X-API-Key: ${API_KEY}" \
  -H 'Content-Type: application/json' \
  -d '{"action":"restart"}'
```

Replace `restart` with `start` or `stop` as needed. The `reset` action clears
the counters exposed by OpenCtrl without changing the Portal configuration:

```sh
curl -X PATCH "${BASE}/instances/${INSTANCE_ID}" \
  -H "X-API-Key: ${API_KEY}" \
  -H 'Content-Type: application/json' \
  -d '{"action":"reset"}'
```

Delete an instance and stop its managed process:

```sh
curl -X DELETE "${BASE}/instances/${INSTANCE_ID}" \
  -H "X-API-Key: ${API_KEY}"
```

### EVENT Metrics

Nowhere emits one checkpoint when the Portal starts and then every
`NOW_REPORT_INTERVAL`, which defaults to five seconds:

```text
CHECK_POINT|MODE=0|PING=0ms|POOL=<n>|TCPS=<n>|UDPS=<n>|TCPRX=<bytes>|TCPTX=<bytes>|UDPRX=<bytes>|UDPTX=<bytes>
```

OpenCtrl consumes these records instead of forwarding them as ordinary log
events. The fields appear on the instance resource as follows:

| EVENT field | OpenCtrl field | Meaning for Nowhere |
| --- | --- | --- |
| `MODE` | `mode` | Fixed at `0` in v1. |
| `PING` | `ping` | Fixed at `0ms` in v1. |
| `POOL` | `pool` | Authenticated TLS/TCP connections waiting for a first request. |
| `TCPS` | `tcps` | Active TCP relay streams. |
| `UDPS` | `udps` | Active QUIC DATAGRAM and UoT flows. |
| `TCPRX` | `tcprx` | Client-to-target TCP bytes. |
| `TCPTX` | `tcptx` | Target-to-client TCP bytes. |
| `UDPRX` | `udprx` | Client-to-target UDP payload bytes. |
| `UDPTX` | `udptx` | Target-to-client UDP payload bytes. |

The byte counters are process-wide for one Portal instance. OpenCtrl maintains
cumulative bases across managed-process restarts and can reset its exposed
totals independently of the child process.

Keep the default five-second reporting interval under OpenCtrl. After receiving
its first checkpoint, OpenCtrl treats more than 15 seconds without another one
as an error. Setting `NOW_REPORT_INTERVAL` to 15 seconds or longer can therefore
produce false health transitions.

### Operational Boundaries

- OpenCtrl treats any ordinary child log line containing `ERROR` as an error
  signal. Nowhere also uses `ERROR` for connection-level failures, so a failed
  handshake or relay can temporarily set the instance status to `error` while
  the Portal remains active. The next valid checkpoint restores `running`.
- On Unix, OpenCtrl stops a child with `SIGTERM`. Nowhere currently installs its
  graceful shutdown path for `Ctrl-C`/`SIGINT`; the default `SIGTERM` action
  exits promptly without running the Portal's explicit drain and flush path.
- The Portal URL contains the shared key. OpenCtrl persists that URL, returns it
  through REST and SSE instance objects, and includes it in process-start logs.
  Protect the API key, state directory, logs, and every management client.
- One OpenCtrl master uses the same configured `bin` path for its managed
  instances, and children inherit the master's environment. Prefer Portal URL
  parameters for per-instance differences. Use separate masters or a trusted
  wrapper when instances require different `NOW_*` environment values.
- Port allocation remains the operator's responsibility. Each Portal instance
  must have a non-conflicting TCP and/or UDP listen address.

## Anywhere Client

[Anywhere](https://github.com/NodePassProject/Anywhere) is a supported native
client for iOS, iPadOS, and tvOS. Its Nowhere implementation supports TCP relay
and UDP traffic over either transport family:

| Anywhere `net` | Portal listener | TCP traffic | UDP traffic |
| --- | --- | --- | --- |
| `udp` | QUIC/UDP | Bidirectional QUIC streams | QUIC DATAGRAM |
| `tcp` | TLS/TCP | Dedicated authenticated connections | UoT connections |

A Portal using `net=mix` accepts either client mode. A Portal restricted to
`net=tcp` or `net=udp` requires the matching Anywhere mode.

### Pair Portal and Client URLs

Run a public Portal with a stable certificate:

```text
portal://change-me@:2077?tls=2&crt=/etc/nowhere/cert.pem&key=/etc/nowhere/key.pem&net=mix&spec=nightfall&alpn=now%2F1
```

Import a QUIC/UDP client configuration in Anywhere:

```text
nowhere://change-me@relay.example.com:2077?net=udp&spec=nightfall&sni=relay.example.com&alpn=now%2F1#Edge
```

Or select TLS/TCP with a warm connection pool:

```text
nowhere://change-me@relay.example.com:2077?net=tcp&pool=5&spec=nightfall&sni=relay.example.com&alpn=now%2F1#Edge
```

The Portal and client must agree on the shared key, `spec`, and ALPN. The
client host is the externally reachable Portal address, not the empty wildcard
host used by the server URL.

### Configuration Mapping

| Setting | Portal URL | Anywhere URL |
| --- | --- | --- |
| Shared key | URL username | URL username; must match exactly. |
| Address | Listen host, which may be empty | Reachable server hostname or IP address. |
| `net` | Enables `tcp`, `udp`, or `mix` listeners | Selects `tcp` or `udp` for this client. |
| `spec` | Protocol-shape seed | Must resolve to the same value; both default to `auto`. |
| `alpn` | TLS/QUIC ALPN | Must resolve to the same value; both default to `now/1`. |
| `sni` | Not used | Certificate server name; defaults to the client host. |
| `pool` | Not used | TLS/TCP warm-pool size `0..9`; valid only with `net=tcp`, defaults to `5`, and `0` disables it. |
| `tls`, `crt`, query `key` | Select and configure the Portal certificate | Not exported; Anywhere always uses TLS and applies its trust policy. |
| `dial`, `rate`, `etar`, `log` | Portal runtime controls | Not part of the client share link. |

The shared key is the URL username. Do not confuse it with the Portal's query
parameter named `key`, which is the PEM private-key path for `tls=2`.

### Certificate Trust

Use `tls=2` with a stable certificate for public or long-lived deployments.
Anywhere can validate the normal platform trust chain or a certificate the user
has explicitly trusted by fingerprint. See the [security notes](security.md)
for the Portal-side trust model.

The `tls=1` Portal certificate is self-signed and regenerated on every process
start. A saved fingerprint therefore stops matching after a restart. Reserve
this mode for controlled testing where the current certificate is explicitly
trusted or Anywhere's global Allow Insecure setting is deliberately enabled.
Do not use Allow Insecure as the trust model for a public deployment.

## More Integrations

The protocol specification is independent of OpenCtrl and Anywhere. Additional
core and client integrations can implement the same authentication, transport,
and frame contracts without changing the Portal.
