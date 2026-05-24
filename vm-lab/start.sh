#!/usr/bin/env bash
# vm-lab/start.sh – Boot 3 QEMU VMs to test the neth overlay network.
#
# Topology
# --------
#   Host bridge  br-neth  192.168.100.1/24
#
#   VM           underlay IP      overlay (neth0)   role
#   lighthouse   192.168.100.10   10.200.0.1/24     lighthouse (am_lighthouse=true)
#   node-a       192.168.100.11   10.200.0.2/24     regular node
#   node-b       192.168.100.12   10.200.0.3/24     regular node
#
# After boot, SSH into any VM from the host:
#   ssh root@192.168.100.10   # lighthouse
#   ssh root@192.168.100.11   # node-a
#   ssh root@192.168.100.12   # node-b
#
# Console logs:  .lab/logs/<vm>.log
# Stop cleanly:  ./stop.sh
#
# Prerequisites (pacman -S <pkg>):
#   qemu-base   – qemu-system-x86_64, qemu-img
#   iproute2    – ip
#   xorriso     – creates the cloud-init CIDATA ISO
#   curl        – image download
#   (KVM is used automatically when /dev/kvm is accessible)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LAB="$SCRIPT_DIR/.lab"

##############################################################################
# Tuneable config
##############################################################################

# Alpine cloud image with cloud-init – supports write_files, runcmd, network-config.
# The "tiny" variant has no cloud-init; use "cloudinit" instead.
ALPINE_VER="3.23.4"
ALPINE_IMG="generic_alpine-${ALPINE_VER}-x86_64-bios-cloudinit-r0.qcow2"
ALPINE_URL="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VER%.*}/releases/cloud/${ALPINE_IMG}"

# Host bridge for VM–VM (underlay) traffic.
BRIDGE="br-neth"
BRIDGE_IP="192.168.100.1"
BRIDGE_CIDR="${BRIDGE_IP}/24"

# Per-VM settings.
NODES=(lighthouse node-a node-b)

declare -A MAC=(
  [lighthouse]="52:54:00:00:10:01"
  [node-a]="52:54:00:00:10:02"
  [node-b]="52:54:00:00:10:03"
)
declare -A PHYS_IP=(
  [lighthouse]="192.168.100.10"
  [node-a]="192.168.100.11"
  [node-b]="192.168.100.12"
)
declare -A VPN_CIDR=(
  [lighthouse]="10.200.0.1/24"
  [node-a]="10.200.0.2/24"
  [node-b]="10.200.0.3/24"
)
declare -A AM_LH=(
  [lighthouse]="true"
  [node-a]="false"
  [node-b]="false"
)

LH_PHYS_IP="${PHYS_IP[lighthouse]}"
LH_VPN_IP="10.200.0.1"
NETH_PORT=4242

# QEMU resources per VM.
VM_MEM="512M"
VM_CPUS="1"

##############################################################################
# Helpers
##############################################################################

info()  { echo "[start] $*"; }
warn()  { echo "[start] WARNING: $*" >&2; }
die()   { echo "[start] ERROR: $*" >&2; exit 1; }

need_cmd() {
  command -v "$1" &>/dev/null || die "required command not found: $1 – install the package that provides it"
}

require_root() {
  [[ $EUID -eq 0 ]] || die "this script must run as root (or with sudo) for bridge/TAP setup"
}

tap_name() {
  # Keep names <= 15 chars (Linux IFNAMSIZ limit).
  local vm="$1"
  case "$vm" in
    lighthouse) echo "tap-neth-lh" ;;
    node-a)     echo "tap-neth-a"  ;;
    node-b)     echo "tap-neth-b"  ;;
    *)          echo "tap-neth-${vm:0:7}" ;;
  esac
}

##############################################################################
# 1. Check prerequisites
##############################################################################

check_deps() {
  info "checking prerequisites …"
  need_cmd qemu-system-x86_64
  need_cmd qemu-img
  need_cmd qemu-nbd
  need_cmd ip
  need_cmd curl
  need_cmd go

  # SSH key – needed so we can log into the VMs.
  SSH_PUBKEY=""
  for candidate in "$HOME/.ssh/id_ed25519.pub" "$HOME/.ssh/id_rsa.pub" "$HOME/.ssh/id_ecdsa.pub"; do
    if [[ -f "$candidate" ]]; then
      SSH_PUBKEY="$(cat "$candidate")"
      info "using SSH public key: $candidate"
      break
    fi
  done
  [[ -n "$SSH_PUBKEY" ]] || die "no SSH public key found in ~/.ssh/. Generate one with: ssh-keygen -t ed25519"
}

##############################################################################
# 2. Build nethd and neth-cert
##############################################################################

build_binaries() {
  info "building nethd and neth-cert …"
  (cd "$ROOT_DIR" && make build 2>&1 | sed 's/^/  /')
  [[ -x "$ROOT_DIR/bin/nethd" ]]      || die "nethd binary not found after build"
  [[ -x "$ROOT_DIR/bin/neth-cert" ]]  || die "neth-cert binary not found after build"
  info "binaries ready: $(ls -lh "$ROOT_DIR"/bin/nethd "$ROOT_DIR"/bin/neth-cert | awk '{print $NF, $5}')"
}

##############################################################################
# 3. Generate PKI (CA + one cert per VM)
##############################################################################

setup_pki() {
  local pki="$LAB/pki"
  if [[ -f "$pki/ca.crt" ]]; then
    info "PKI already exists – skipping cert generation (delete $pki to regenerate)"
    return
  fi

  info "generating CA and node certificates …"
  mkdir -p "$pki"

  "$ROOT_DIR/bin/neth-cert" ca \
    --name "neth-lab-ca" \
    --duration 8760h \
    --out-dir "$pki"

  for vm in "${NODES[@]}"; do
    "$ROOT_DIR/bin/neth-cert" sign \
      --ca-crt "$pki/neth-lab-ca.crt" \
      --ca-key "$pki/neth-lab-ca.key" \
      --name   "$vm" \
      --ip     "${VPN_CIDR[$vm]}" \
      --groups "neth-lab" \
      --duration 8760h \
      --out-dir "$pki"
  done

  info "PKI written to $pki/"
}

##############################################################################
# 4. Write neth config files
##############################################################################

write_configs() {
  local cfgs="$LAB/configs"
  mkdir -p "$cfgs"

  info "writing neth configs …"

  for vm in "${NODES[@]}"; do
    local am_lh="${AM_LH[$vm]}"
    local lh_hosts_yaml=""

    # Build a full static_host_map: every peer's VPN IP → physical address.
    # This lets every node initiate direct handshakes without lighthouse queries.
    local static_map_entries=""
    for peer in "${NODES[@]}"; do
      [[ "$peer" == "$vm" ]] && continue
      local peer_vpn="${VPN_CIDR[$peer]%%/*}"
      static_map_entries+="  \"${peer_vpn}\": [\"${PHYS_IP[$peer]}:${NETH_PORT}\"]"$'\n'
    done
    local static_map_yaml
    if [[ -n "$static_map_entries" ]]; then
      static_map_yaml="static_host_map:
${static_map_entries}"
    else
      static_map_yaml="static_host_map: {}"
    fi

    if [[ "$am_lh" == "false" ]]; then
      lh_hosts_yaml="  hosts:
    - \"${LH_VPN_IP}\""
    fi

    cat > "$cfgs/$vm.yaml" <<YAML
pki:
  ca:        /etc/neth/ca.crt
  cert:      /etc/neth/${vm}.crt
  key:       /etc/neth/${vm}.key
  peers_dir: /etc/neth/peers

listen:
  host: 0.0.0.0
  port: ${NETH_PORT}

tun:
  dev: neth0
  mtu: 1300

lighthouse:
  am_lighthouse: ${am_lh}
  interval: 60
${lh_hosts_yaml}

${static_map_yaml}

punchy:
  punch: true
  respond: true

firewall:
  inbound:
    - port: any
      proto: any
  outbound:
    - port: any
      proto: any

logging:
  level: info
  format: text
YAML
  done

  info "configs written to $cfgs/"
}

##############################################################################
# 5. Download Alpine cloud image (cached)
##############################################################################

download_image() {
  local cache="$LAB/cache"
  mkdir -p "$cache"

  if [[ -f "$cache/$ALPINE_IMG" ]]; then
    info "Alpine image already cached – skipping download"
    return
  fi

  info "downloading Alpine Linux cloud image (~50 MB) …"
  curl -fL --progress-bar -o "$cache/$ALPINE_IMG" "$ALPINE_URL"

  info "base image: $cache/$ALPINE_IMG"
}

##############################################################################
# 6. Build per-VM overlay disks (copy-on-write over the base image)
##############################################################################

make_disks() {
  local cache="$LAB/cache"
  local disks="$LAB/disks"
  mkdir -p "$disks"

  for vm in "${NODES[@]}"; do
    if [[ -f "$disks/$vm.qcow2" ]]; then
      info "disk $vm.qcow2 already exists – skipping"
      continue
    fi
    info "creating overlay disk for $vm …"
    qemu-img create -f qcow2 \
      -b "$cache/$ALPINE_IMG" \
      -F qcow2 \
      "$disks/$vm.qcow2" \
      2>&1 | sed 's/^/  /'
  done
}

##############################################################################
# 7. Provision each VM disk directly via qemu-nbd (no cloud-init required)
##############################################################################

provision_disks() {
  local disks="$LAB/disks"
  local pki="$LAB/pki"
  local cfgs="$LAB/configs"

  # Load NBD kernel module (idempotent).
  modprobe nbd max_part=8 2>/dev/null || true
  # Ensure the NBD device is free from any previous failed run.
  qemu-nbd --disconnect /dev/nbd0 2>/dev/null || true

  info "provisioning VM disks …"

  for vm in "${NODES[@]}"; do
    local disk="$disks/$vm.qcow2"
    local marker="$disks/$vm.provisioned"

    if [[ -f "$marker" ]]; then
      info "  $vm already provisioned – skipping"
      continue
    fi

    info "  provisioning $vm …"

    local mnt
    mnt="$(mktemp -d /tmp/neth-lab-XXXXXX)"

    qemu-nbd --connect=/dev/nbd0 "$disk"
    sleep 2  # wait for partition devices to appear

    # Probe common Alpine partition layouts to find the root filesystem.
    local root_dev=""
    for part in /dev/nbd0p1 /dev/nbd0p2 /dev/nbd0p3 /dev/nbd0; do
      [[ -b "$part" ]] || continue
      if mount "$part" "$mnt" 2>/dev/null; then
        if [[ -d "$mnt/etc/init.d" && -d "$mnt/usr" ]]; then
          root_dev="$part"
          break
        fi
        umount "$mnt"
      fi
    done

    if [[ -z "$root_dev" ]]; then
      umount "$mnt" 2>/dev/null || true
      rmdir "$mnt"
      qemu-nbd --disconnect /dev/nbd0 2>/dev/null || true
      die "could not find root partition in $disk"
    fi

    # ── Disable cloud-init entirely ───────────────────────────────────────
    # We provision everything via qemu-nbd; cloud-init is not needed and
    # its ds-identify scan (EC2/Azure/GCP probes) causes multi-minute hangs.
    mkdir -p "$mnt/etc/cloud"
    touch "$mnt/etc/cloud/cloud-init.disabled"

    # ── hostname ─────────────────────────────────────────────────────────
    echo "$vm" > "$mnt/etc/hostname"

    # ── root password (for console access; password: "alpine") ────────────
    # Generate a SHA-512 shadow hash; fall back to a pre-computed one if
    # openssl is not available.
    local root_hash
    if command -v openssl &>/dev/null; then
      root_hash="$(openssl passwd -6 -salt 'neth-lab0' 'alpine')"
    else
      # Pre-computed SHA-512 hash for "alpine" with salt "neth-lab0"
      root_hash='$6$neth-lab0$Wg6HpNkMJBBWaHiGOlGVSEExWVR0gIxDioAKVBm.Iqon8xoIh0qEnGbLOdPbH7OeefQ.7NeG3R7kGiQmBvgm91'
    fi
    if [[ -f "$mnt/etc/shadow" ]]; then
      sed -i "s|^root:[^:]*:|root:${root_hash}:|" "$mnt/etc/shadow"
    fi

    # ── SSH public key ────────────────────────────────────────────────────
    mkdir -p "$mnt/root/.ssh"
    chmod 700 "$mnt/root/.ssh"
    printf '%s\n' "$SSH_PUBKEY" > "$mnt/root/.ssh/authorized_keys"
    chmod 600 "$mnt/root/.ssh/authorized_keys"

    # ── Force NIC name to eth0 regardless of udev predictable naming ──────
    mkdir -p "$mnt/etc/udev/rules.d"
    printf 'SUBSYSTEM=="net", ACTION=="add", ATTR{address}=="%s", NAME="eth0"\n' \
      "${MAC[$vm]}" > "$mnt/etc/udev/rules.d/70-persistent-net.rules"

    # ── Static networking ─────────────────────────────────────────────────
    cat > "$mnt/etc/network/interfaces" <<NETCFG
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
    address ${PHYS_IP[$vm]}/24
    gateway ${BRIDGE_IP}
NETCFG

    # ── neth PKI and config ───────────────────────────────────────────────
    mkdir -p "$mnt/etc/neth/peers"
    cp "$pki/neth-lab-ca.crt"  "$mnt/etc/neth/ca.crt"
    cp "$pki/${vm}.crt"        "$mnt/etc/neth/${vm}.crt"
    cp "$pki/${vm}.key"        "$mnt/etc/neth/${vm}.key"
    cp "$cfgs/${vm}.yaml"      "$mnt/etc/neth/config.yaml"
    chmod 600 "$mnt/etc/neth/${vm}.key"
    # Copy all peer node certs so nethd can pre-seed them (Noise IK requires
    # the initiator to know the responder's public key before handshake).
    for peer in "${NODES[@]}"; do
      cp "$pki/${peer}.crt" "$mnt/etc/neth/peers/${peer}.crt"
    done

    # ── nethd binary ──────────────────────────────────────────────────────
    cp "$ROOT_DIR/bin/nethd" "$mnt/usr/local/bin/nethd"
    chmod 755 "$mnt/usr/local/bin/nethd"

    # ── Load tun module at boot ───────────────────────────────────────────
    echo "tun" >> "$mnt/etc/modules"

    # ── nethd OpenRC init script ──────────────────────────────────────────
    cat > "$mnt/etc/init.d/nethd" <<'INITD'
#!/sbin/openrc-run
name="nethd"
description="neth overlay network daemon"
command="/usr/local/bin/nethd"
command_args="-config /etc/neth/config.yaml"
command_background=true
pidfile="/run/nethd.pid"
output_log="/var/log/nethd.log"
error_log="/var/log/nethd.log"

start_pre() {
    modprobe tun 2>/dev/null || true
    mkdir -p /dev/net
    [ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200 2>/dev/null || true
}

depend() {
    need net
    after firewall
}
INITD
    chmod 755 "$mnt/etc/init.d/nethd"

    # ── Enable services via runlevel symlinks ─────────────────────────────
    mkdir -p "$mnt/etc/runlevels/boot" "$mnt/etc/runlevels/default"

    # networking at boot
    if [[ -f "$mnt/etc/init.d/networking" ]]; then
      ln -sf /etc/init.d/networking "$mnt/etc/runlevels/boot/networking" 2>/dev/null || true
    fi

    # sshd at default
    if [[ -f "$mnt/etc/init.d/sshd" ]]; then
      ln -sf /etc/init.d/sshd "$mnt/etc/runlevels/default/sshd" 2>/dev/null || true
    elif [[ -f "$mnt/etc/init.d/openssh" ]]; then
      ln -sf /etc/init.d/openssh "$mnt/etc/runlevels/default/openssh" 2>/dev/null || true
    fi

    # nethd at default
    ln -sf /etc/init.d/nethd "$mnt/etc/runlevels/default/nethd" 2>/dev/null || true

    # ── Cleanup ───────────────────────────────────────────────────────────
    umount "$mnt"
    rmdir "$mnt"
    qemu-nbd --disconnect /dev/nbd0
    touch "$marker"
    info "  $vm provisioned"
  done
}

##############################################################################
# 8. Set up host bridge and TAP devices (requires root)
##############################################################################

setup_network() {
  info "setting up bridge ${BRIDGE} and TAP devices …"

  # Create bridge if it doesn't exist.
  if ! ip link show "$BRIDGE" &>/dev/null; then
    ip link add name "$BRIDGE" type bridge
    ip addr add "$BRIDGE_CIDR" dev "$BRIDGE"
    ip link set "$BRIDGE" up
    info "  bridge ${BRIDGE} created (${BRIDGE_CIDR})"
  else
    info "  bridge ${BRIDGE} already exists"
  fi

  for vm in "${NODES[@]}"; do
    local tap
    tap="$(tap_name "$vm")"

    if ! ip link show "$tap" &>/dev/null; then
      ip tuntap add dev "$tap" mode tap
      ip link set "$tap" master "$BRIDGE"
      ip link set "$tap" up
      info "  TAP $tap created and added to ${BRIDGE}"
    else
      info "  TAP $tap already exists"
    fi
  done
}

##############################################################################
# 9. Start QEMU VMs
##############################################################################

start_vms() {
  local pids="$LAB/pids"
  local logs="$LAB/logs"
  local disks="$LAB/disks"
  mkdir -p "$pids" "$logs"

  local kvm_flag=""
  if [[ -w /dev/kvm ]]; then
    kvm_flag="-enable-kvm -cpu host"
    info "KVM acceleration enabled"
  else
    warn "/dev/kvm not writable – running without KVM (expect slow boot)"
  fi

  for vm in "${NODES[@]}"; do
    local pidfile="$pids/$vm.pid"
    if [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
      info "VM $vm already running (PID $(cat "$pidfile")) – skipping"
      continue
    fi

    local tap
    tap="$(tap_name "$vm")"

    info "starting VM $vm …"

    # shellcheck disable=SC2086
    qemu-system-x86_64 \
      $kvm_flag \
      -m "$VM_MEM" \
      -smp "$VM_CPUS" \
      -vga none \
      -smbios "type=1,serial=ds=nocloud" \
      -drive  "file=$disks/$vm.qcow2,if=virtio,format=qcow2" \
      -netdev "tap,id=net0,ifname=${tap},script=no,downscript=no" \
      -device "virtio-net-pci,netdev=net0,mac=${MAC[$vm]}" \
      -display none \
      -serial "file:$logs/$vm.log" \
      -monitor "unix:$LAB/$vm.mon,server,nowait" \
      -name   "$vm" \
      -daemonize \
      -pidfile "$pidfile"

    info "  $vm started (PID $(cat "$pidfile"))"
  done
}

##############################################################################
# 10. Print connection info
##############################################################################

print_info() {
  local logs="$LAB/logs"

  echo
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  neth vm-lab is running"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  printf "  %-12s  %-18s  %-18s\n" "VM" "underlay IP" "neth (overlay) IP"
  printf "  %-12s  %-18s  %-18s\n" "──────────" "────────────────" "─────────────────"
  for vm in "${NODES[@]}"; do
    printf "  %-12s  %-18s  %-18s\n" "$vm" "${PHYS_IP[$vm]}" "${VPN_CIDR[$vm]}"
  done
  echo
  echo "  SSH (wait ~30 s for boot to finish):"
  for vm in "${NODES[@]}"; do
    echo "    ssh root@${PHYS_IP[$vm]}   # $vm"
  done
  echo
  echo "  Console logs:"
  for vm in "${NODES[@]}"; do
    echo "    tail -f $logs/$vm.log   # $vm"
  done
  echo
  echo "  QEMU monitor (e.g. 'info status', 'quit'):"
  for vm in "${NODES[@]}"; do
    echo "    socat - UNIX-CONNECT:$LAB/$vm.mon   # $vm"
  done
  echo
  echo "  Quick connectivity test (run from any VM after overlay is up):"
  echo "    ping -c3 10.200.0.1   # reach lighthouse"
  echo "    ping -c3 10.200.0.2   # reach node-a"
  echo "    ping -c3 10.200.0.3   # reach node-b"
  echo
  echo "  Stop everything:  $SCRIPT_DIR/stop.sh"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

##############################################################################
# Main
##############################################################################

main() {
  require_root
  check_deps
  build_binaries
  setup_pki
  write_configs
  download_image
  make_disks
  provision_disks
  setup_network
  start_vms
  print_info
}

main "$@"
