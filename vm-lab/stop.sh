#!/usr/bin/env bash
# vm-lab/stop.sh – Gracefully shut down all neth lab VMs and clean up the
# host bridge / TAP devices created by start.sh.
#
# Pass --clean to also delete the per-VM overlay disks and cloud-init ISOs
# (the cached Alpine base image and PKI are kept so the next start.sh run
# skips the slow steps).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB="$SCRIPT_DIR/.lab"

BRIDGE="br-neth"
NODES=(lighthouse node-a node-b)

info() { echo "[stop] $*"; }
warn() { echo "[stop] WARNING: $*" >&2; }

require_root() {
  [[ $EUID -eq 0 ]] || { echo "[stop] ERROR: must run as root"; exit 1; }
}

tap_name() {
  case "$1" in
    lighthouse) echo "tap-neth-lh" ;;
    node-a)     echo "tap-neth-a"  ;;
    node-b)     echo "tap-neth-b"  ;;
    *)          echo "tap-neth-${1:0:7}" ;;
  esac
}

##############################################################################
# Stop VMs
##############################################################################

stop_vms() {
  local pids="$LAB/pids"
  [[ -d "$pids" ]] || return

  for vm in "${NODES[@]}"; do
    local pidfile="$pids/$vm.pid"
    if [[ ! -f "$pidfile" ]]; then
      info "no PID file for $vm – already stopped"
      continue
    fi

    local pid
    pid="$(cat "$pidfile")"

    if kill -0 "$pid" 2>/dev/null; then
      # Send ACPI powerdown via the QEMU monitor (graceful shutdown).
      local mon="$LAB/$vm.mon"
      if [[ -S "$mon" ]]; then
        info "sending ACPI powerdown to $vm (PID $pid) …"
        echo "system_powerdown" | socat - "UNIX-CONNECT:$mon" 2>/dev/null || true
        # Give the VM up to 10 s to halt cleanly.
        local deadline=$(( $(date +%s) + 10 ))
        while kill -0 "$pid" 2>/dev/null && [[ $(date +%s) -lt $deadline ]]; do
          sleep 1
        done
      fi

      # Force-kill if still running.
      if kill -0 "$pid" 2>/dev/null; then
        warn "$vm did not halt in time – sending SIGKILL"
        kill -9 "$pid" 2>/dev/null || true
      fi
      info "  $vm stopped"
    else
      info "  $vm was not running"
    fi

    rm -f "$pidfile"
    rm -f "$LAB/$vm.mon"
  done
}

##############################################################################
# Tear down TAP devices and bridge
##############################################################################

teardown_network() {
  for vm in "${NODES[@]}"; do
    local tap
    tap="$(tap_name "$vm")"
    if ip link show "$tap" &>/dev/null; then
      ip link set "$tap" down
      ip link delete "$tap"
      info "removed TAP $tap"
    fi
  done

  if ip link show "$BRIDGE" &>/dev/null; then
    ip link set "$BRIDGE" down
    ip link delete "$BRIDGE"
    info "removed bridge $BRIDGE"
  fi
}

##############################################################################
# Optional: delete regeneratable artefacts
##############################################################################

clean_artefacts() {
  info "removing overlay disks …"
  rm -rf "$LAB/disks" "$LAB/cidata"
  info "kept: $LAB/cache (Alpine base image), $LAB/pki, $LAB/configs"
}

##############################################################################
# Main
##############################################################################

CLEAN=false
for arg in "$@"; do
  [[ "$arg" == "--clean" ]] && CLEAN=true
done

require_root
stop_vms
teardown_network

if $CLEAN; then
  clean_artefacts
fi

info "done"
