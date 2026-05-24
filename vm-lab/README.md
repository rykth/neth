# neth vm-lab

A self-contained QEMU lab that boots three Alpine Linux VMs and wires them together to form a working neth overlay network — one lighthouse and two regular nodes.

## Topology

```
Host machine
│
├── br-neth  192.168.100.1/24  (Linux bridge, created by start.sh)
│   ├── tap-neth-lh ──► VM: lighthouse   underlay 192.168.100.10   neth0 10.200.0.1/24
│   ├── tap-neth-a  ──► VM: node-a       underlay 192.168.100.11   neth0 10.200.0.2/24
│   └── tap-neth-b  ──► VM: node-b       underlay 192.168.100.12   neth0 10.200.0.3/24
│
└── SSH from host → any VM via its underlay IP (192.168.100.x)
```

The **underlay** (192.168.100.0/24) is the simulated physical network — the "internet" the VMs share. The VMs reach each other over it using plain UDP.

The **overlay** (10.200.0.0/24) is the neth encrypted network. Once `nethd` is running, you can ping across it regardless of what the underlay looks like.

## Prerequisites

Install the required packages (Arch Linux):

```bash
pacman -S qemu-base curl
```

| Package | Provides | Used for |
|---|---|---|
| `qemu-base` | `qemu-system-x86_64`, `qemu-img`, `qemu-nbd` | running VMs, managing disk images, and mounting qcow2 overlays for provisioning |
| `curl` | `curl` | downloading the Alpine base image |

You also need:

- **Root / sudo** — creating TAP devices and the host bridge requires `CAP_NET_ADMIN`.
- **An SSH key pair** — `start.sh` reads `~/.ssh/id_ed25519.pub` (or `id_rsa.pub` / `id_ecdsa.pub`) and injects it into each VM so you can log in. If you don't have one yet:
  ```bash
  ssh-keygen -t ed25519
  ```
- **KVM** (optional but recommended) — if `/dev/kvm` is accessible the VMs will use hardware acceleration and boot in a few seconds instead of 30–60 s. Add yourself to the `kvm` group if needed:
  ```bash
  sudo usermod -aG kvm "$USER"   # log out and back in
  ```

## Quick start

```bash
# From the repo root — builds binaries then boots the lab:
make vm-start

# or equivalently:
sudo ./vm-lab/start.sh
```

`start.sh` runs fully unattended. On the **first run** it downloads the Alpine cloud image (~50 MB) and generates the PKI; both are cached for subsequent runs.

Wait about 30 seconds for the VMs to finish booting, then SSH in:

```bash
ssh root@192.168.100.10   # lighthouse
ssh root@192.168.100.11   # node-a
ssh root@192.168.100.12   # node-b
```

## Testing the overlay

From any VM, ping the others over the neth overlay:

```bash
# from node-a (10.200.0.2)
ping -c3 10.200.0.1   # → lighthouse
ping -c3 10.200.0.3   # → node-b
```

Check that `nethd` is running and review its log:

```bash
rc-service nethd status
tail -f /var/log/nethd.log
```

## Stopping the lab

```bash
# Graceful ACPI shutdown + remove bridge/TAP:
make vm-stop
# or:
sudo ./vm-lab/stop.sh

# Shutdown + delete overlay disks and cloud-init ISOs
# (Alpine base image and PKI are kept for fast restarts):
make vm-clean
# or:
sudo ./vm-lab/stop.sh --clean
```

## What start.sh does (step by step)

| Step | Action |
|---|---|
| 1 | Checks for required commands and an SSH public key |
| 2 | Builds `nethd` and `neth-cert` via `make build` |
| 3 | Generates a CA (`neth-lab-ca`) and one signed cert/key per VM using `neth-cert sign` |
| 4 | Writes a `nethd` config file per VM; the lighthouse sets `am_lighthouse: true`, the nodes point their `static_host_map` and `lighthouse.hosts` at `192.168.100.10:4242` |
| 5 | Downloads the Alpine Linux nocloud cloud image (cached in `.lab/cache/`) |
| 6 | Creates a thin copy-on-write QCOW2 overlay disk per VM on top of the shared base image |
| 7 | Builds a cloud-init CIDATA ISO per VM containing the PKI files, config, and `nethd` binary (base64-embedded), plus `runcmd` directives that set a static IP and register `nethd` as an OpenRC service |
| 8 | Creates bridge `br-neth` (192.168.100.1/24) on the host and attaches one TAP device per VM to it |
| 9 | Launches three QEMU VMs in daemon mode; each VM's console is redirected to `.lab/logs/<vm>.log` |
| 10 | Prints a summary table with SSH addresses, log paths, and test commands |

## Generated file layout

All runtime artefacts live under `vm-lab/.lab/` (gitignored):

```
vm-lab/.lab/
├── cache/                  Alpine base image (kept across runs)
│   └── nocloud_alpine-*.qcow2
├── pki/                    CA and per-VM certs/keys (kept across runs)
│   ├── neth-lab-ca.crt / .key
│   ├── lighthouse.crt / .key
│   ├── node-a.crt / .key
│   └── node-b.crt / .key
├── configs/                nethd config files written into each VM
│   ├── lighthouse.yaml
│   ├── node-a.yaml
│   └── node-b.yaml
├── disks/                  Per-VM copy-on-write overlay disks (recreated by --clean)
│   ├── lighthouse.qcow2
│   ├── node-a.qcow2
│   └── node-b.qcow2
├── cidata/                 cloud-init CIDATA ISOs (recreated by --clean)
│   ├── lighthouse.iso
│   ├── node-a.iso
│   └── node-b.iso
├── logs/                   Serial console output per VM
│   ├── lighthouse.log
│   ├── node-a.log
│   └── node-b.log
├── pids/                   QEMU PID files (used by stop.sh)
│   ├── lighthouse.pid
│   ├── node-a.pid
│   └── node-b.pid
└── <vm>.mon                QEMU monitor UNIX sockets (removed on stop)
```

## QEMU monitor access

Each VM exposes a QEMU monitor socket. Connect with `socat`:

```bash
socat - UNIX-CONNECT:vm-lab/.lab/lighthouse.mon
```

Useful monitor commands:

| Command | Effect |
|---|---|
| `info status` | show VM run state |
| `info network` | show virtual NICs |
| `system_powerdown` | ACPI power-off (same as stop.sh) |
| `quit` | force-terminate the QEMU process |

## Regenerating the PKI

Delete `.lab/pki/` and re-run `start.sh`. New certs are generated, new CIDATA ISOs are built, and the overlay disks are recreated:

```bash
sudo rm -rf vm-lab/.lab/pki vm-lab/.lab/disks vm-lab/.lab/cidata
make vm-start
```

## Makefile targets

| Target | Description |
|---|---|
| `make vm-start` | Build binaries, then boot the lab (calls `start.sh`) |
| `make vm-stop` | Graceful shutdown + remove bridge/TAP (calls `stop.sh`) |
| `make vm-clean` | Shutdown + delete overlay disks and cloud-init ISOs |
