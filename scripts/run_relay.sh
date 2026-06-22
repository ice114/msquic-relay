#!/usr/bin/env bash
# Launch the DPDK relay on the VM. Run setup_relay.sh first.
#
# EAL: pin to lcores 0-1, allow ONLY the data NIC PCI (so the relay can't
# touch the management NIC). App args follow `--`.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
RELAY="${RELAY_BIN:-$HERE/relay/build/relay}"
DATA_PCI="${DATA_PCI:-0000:0b:00.0}"

RELAY_IP="${RELAY_IP:-10.103.238.111}"
RELAY_PORT="${RELAY_PORT:-4433}"
THRESHOLD_MBPS="${THRESHOLD_MBPS:-10}"

if [ ! -x "$RELAY" ]; then
  echo "relay binary not found at $RELAY — build it first:" >&2
  echo "  PKG_CONFIG_PATH=/usr/local/lib/x86_64-linux-gnu/pkgconfig meson setup relay/build relay && ninja -C relay/build" >&2
  exit 1
fi

exec sudo "$RELAY" -l 0-1 -a "$DATA_PCI" -- \
  --relay-ip "$RELAY_IP" \
  --relay-port "$RELAY_PORT" \
  --threshold-mbps "$THRESHOLD_MBPS"
