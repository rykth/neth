# Neth

Neth is an encrypted overlay network daemon for Linux. It connects hosts across
the internet into a flat virtual network where every node gets a stable VPN IP,
all traffic is encrypted end-to-end with AES-256-GCM, and peers discover each
other through a lightweight lighthouse protocol with NAT traversal built in.

## How It Works

Each node runs `nethd`, which creates a TUN interface (`neth0`) and a UDP
socket. Outbound IP packets written to the TUN device are encrypted and sent as
UDP datagrams to the destination peer. Inbound UDP datagrams are decrypted and
injected back into the TUN device. The result is a transparent encrypted tunnel
between any two nodes in the network.

Peer discovery is handled by one or more **lighthouse** nodes that maintain a
registry of VPN IP to physical address mappings. Regular nodes periodically
advertise their addresses to the lighthouses and query them when they need to
reach a new peer.

**NAT traversal** is supported via UDP hole-punching. When a node behind NAT
needs to be reached, the lighthouse instructs it to send punch packets toward
the initiator, opening the NAT mapping so the handshake can complete.

Sessions are established using the **Noise IKpsk0** protocol (Curve25519,
AES-GCM, SHA-256) with a pre-shared key derived from the X.509 certificates of
both peers. Every node has a certificate signed by a shared CA -- mutual
authentication happens during the handshake, and only nodes with valid
certificates can join the network.

## Features

- **End-to-end encryption** -- AES-256-GCM with per-packet nonces; wire headers bound as AEAD additional data
- **Certificate-based identity** -- X.509 certificates with custom extensions for VPN IP, group membership, and X25519 public keys
- **Peer discovery** -- Lighthouse nodes maintain a distributed address registry
- **NAT traversal** -- UDP hole-punching with configurable punch/respond behavior
- **Stateful firewall** -- Inbound/outbound rules with connection tracking and protocol-aware expiry
- **Replay protection** -- Sliding-window bitmap (4096 counter slots) per session
- **Forward secrecy** -- Noise protocol ephemeral keys; each handshake produces fresh session keys
- **Minimal dependencies** -- Pure Go with only `flynn/noise`, `x/crypto`, `x/sys`, and `protobuf`

## Quick Start

### 1. Build

```bash
make build
```

This produces two binaries in `bin/`:
- `nethd` -- the overlay network daemon
- `neth-cert` -- certificate management CLI

### 2. Create a CA

```bash
neth-cert ca --name my-network --duration 8760h --out-dir /etc/neth
```

This generates:
- `my-network.crt` -- CA certificate (distribute to all nodes)
- `my-network.key` -- CA private key (keep secret, used only to sign node certs)

### 3. Issue Node Certificates

On each node (or centrally), generate a certificate and key pair:

```bash
# Lighthouse node
neth-cert sign \
  --ca-crt /etc/neth/my-network.crt \
  --ca-key /etc/neth/my-network.key \
  --name lighthouse \
  --ip 10.0.0.1/24 \
  --groups lighthouse \
  --out-dir /etc/neth

# Regular node
neth-cert sign \
  --ca-crt /etc/neth/my-network.crt \
  --ca-key /etc/neth/my-network.key \
  --name node-a \
  --ip 10.0.0.2/24 \
  --groups servers \
  --out-dir /etc/neth
```

Each `sign` command produces:
- `<name>.crt` -- node certificate (contains VPN IP, groups, X25519 public key)
- `<name>.key` -- X25519 private key for the Noise handshake

### 4. Verify a Certificate

```bash
neth-cert verify --ca-crt /etc/neth/my-network.crt --cert /etc/neth/node-a.crt
```

### 5. Inspect a Certificate

```bash
neth-cert print --cert /etc/neth/node-a.crt
```

### 6. Configure

Create `/etc/neth/config.yaml`. See [`dist/example.yaml`](dist/example.yaml) for
a fully commented reference.

**Lighthouse node:**

```yaml
pki:
  ca:   /etc/neth/my-network.crt
  cert: /etc/neth/lighthouse.crt
  key:  /etc/neth/lighthouse.key

listen:
  port: 4242

lighthouse:
  am_lighthouse: true

firewall:
  inbound:
    - port: any
      proto: any
      group: any
  outbound:
    - port: any
      proto: any
      group: any
```

**Regular node:**

```yaml
pki:
  ca:   /etc/neth/my-network.crt
  cert: /etc/neth/node-a.crt
  key:  /etc/neth/node-a.key

listen:
  port: 4242

lighthouse:
  hosts:
    - "10.0.0.1"

static_host_map:
  "10.0.0.1": ["203.0.113.1:4242"]

punchy:
  punch: true
  respond: true

firewall:
  inbound:
    - port: any
      proto: icmp
      group: any
    - port: "22"
      proto: tcp
      group: ops
    - port: "443"
      proto: tcp
      cidr: "10.0.0.0/24"
  outbound:
    - port: any
      proto: any
      group: any
```

### 7. Run

```bash
sudo nethd -config /etc/neth/config.yaml
```

Or install as a systemd service using the provided unit file:

```bash
sudo cp bin/nethd /usr/local/bin/
sudo cp dist/nethd.service /etc/systemd/system/
sudo useradd --system --no-create-home neth
sudo systemctl enable --now nethd
```

The service runs with minimal privileges (`CAP_NET_ADMIN` and `CAP_NET_RAW`
only) under a dedicated `neth` user.

### 8. Test

```bash
# From node-a (10.0.0.2)
ping 10.0.0.1
```

## Configuration Reference

| Section | Key | Default | Description |
|---|---|---|---|
| `pki` | `ca` | -- | Path to CA certificate (required) |
| `pki` | `cert` | -- | Path to node certificate (required) |
| `pki` | `key` | -- | Path to X25519 private key (required) |
| `listen` | `host` | `0.0.0.0` | UDP bind address |
| `listen` | `port` | -- | UDP port (required, 1-65535) |
| `tun` | `dev` | `neth0` | TUN interface name |
| `tun` | `mtu` | `1300` | Interface MTU |
| `lighthouse` | `am_lighthouse` | `false` | Set `true` on lighthouse nodes |
| `lighthouse` | `interval` | `60` | Address re-advertisement interval (seconds) |
| `lighthouse` | `hosts` | `[]` | VPN IPs of lighthouse nodes |
| `static_host_map` | -- | `{}` | VPN IP to physical address bootstrap map |
| `punchy` | `punch` | `false` | Send hole-punch packets |
| `punchy` | `respond` | `false` | Respond to unrecognized UDP |
| `firewall` | `inbound` | `[]` | Inbound rules (deny-all if empty) |
| `firewall` | `outbound` | `[]` | Outbound rules (deny-all if empty) |
| `logging` | `level` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `logging` | `format` | `text` | Log format: `text` or `json` |

### Firewall Rules

Rules are evaluated in order; first match wins. Both directions default to
deny-all when no rules are defined.

```yaml
- port: "443"          # "any" or 0-65535
  proto: tcp           # "any", "tcp", "udp", "icmp"
  group: servers       # cert group name, or "any"
  cidr: "10.0.0.0/24"  # CIDR range, or "any"
```

The firewall includes connection tracking -- once a flow is allowed, return
traffic is automatically permitted. Tracked connections expire based on
protocol: TCP after 5 minutes, UDP after 30 seconds, ICMP after 10 seconds.

## Architecture

See [`docs/architecture.md`](docs/architecture.md) for detailed diagrams
covering the packet flow, handshake protocol, wire format, certificate model,
and goroutine structure.

### Package Layout

```
cmd/
  nethd/              daemon entry point
  neth-cert/          certificate management CLI
cert/                 X.509 certificate parsing, signing, key generation
config/               YAML configuration loading and validation
firewall/             stateful packet filter with connection tracking
handshake/            Noise IKpsk0 protocol messages and state machines
header/               16-byte wire header encoding/decoding
nethpb/               protobuf definitions (lighthouse + handshake messages)
noiseutil/            AES-256-GCM AEAD helpers for Noise cipher states
tun/                  Linux TUN device management (ioctl-based)
udp/                  UDP socket with SO_REUSEPORT
dist/                 example config, systemd unit file
e2e/                  integration tests (two-node, lighthouse)
```

### Key Types

| Component | Purpose |
|---|---|
| `Interface` | Central orchestrator: wires TUN, UDP, firewall, handshake, and lighthouse |
| `HostMap` | Thread-safe registry of active peer sessions (by VPN IP and session index) |
| `HostInfo` | Per-peer session state: ciphers, counters, replay window, remote address |
| `HandshakeManager` | Initiates/responds to Noise handshakes with retry and packet queuing |
| `LightHouse` | Peer address registry and discovery protocol |
| `Punchy` | UDP hole-punching for NAT traversal |
| `PKI` | Loaded CA certs, node cert, and Curve25519 private key |
| `Firewall` | Rule-based packet filter with bidirectional connection tracking |

## Development

```bash
make test          # run all unit tests
make test-race     # run with race detector
make lint          # run golangci-lint
make proto         # regenerate protobuf bindings
make clean         # remove compiled binaries
```

## Requirements

- Linux (TUN device support)
- Go 1.25+
- `CAP_NET_ADMIN` and `CAP_NET_RAW` capabilities (or root)

