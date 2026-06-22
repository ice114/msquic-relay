#!/usr/bin/env bash
# One-time DPDK environment setup on the relay VM (run as / via sudo).
#   - reserve hugepages
#   - load vfio-pci
#   - bind the DATA NIC (ens192 / PCI 0000:0b:00.0) to vfio-pci
#
# WARNING: binding ens192 to DPDK removes its kernel IP (10.103.238.111).
# SSH must stay on the MANAGEMENT NIC ens160 (10.103.238.110) — do not bind it.
set -euo pipefail

DATA_PCI="${DATA_PCI:-0000:0b:00.0}"      # ens192
HUGEPAGES="${HUGEPAGES:-1024}"            # 1024 * 2MB = 2GB
DEVBIND="$(command -v dpdk-devbind.py || echo /usr/local/bin/dpdk-devbind.py)"

echo "== hugepages =="
echo "$HUGEPAGES" | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages >/dev/null
sudo mkdir -p /dev/hugepages
mountpoint -q /dev/hugepages || sudo mount -t hugetlbfs nodev /dev/hugepages
grep -i huge /proc/meminfo | head -3

echo "== vfio-pci =="
sudo modprobe vfio-pci
# VMware/no-IOMMU fallback: allow vfio without IOMMU if needed.
if [ -e /sys/module/vfio/parameters/enable_unsafe_noiommu_mode ]; then
  echo 1 | sudo tee /sys/module/vfio/parameters/enable_unsafe_noiommu_mode >/dev/null || true
fi

echo "== bind $DATA_PCI to vfio-pci =="
sudo ip link set ens192 down 2>/dev/null || true
sudo python3 "$DEVBIND" -b vfio-pci "$DATA_PCI"
python3 "$DEVBIND" -s | grep -A2 "DPDK-compatible"

echo "Done. ens192 is now under DPDK; SSH stays on ens160 (10.103.238.110)."
