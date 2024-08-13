#!/bin/bash

set -euo pipefail

# Variables
VIRTIO_ISO_URL="https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso"
VIRTIO_ISO="/var/lib/libvirt/images/virtio-win.iso"

# Check if ISO path is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <path_to_windows_iso>"
    exit 1
else
    ISO_PATH=$1
fi

# Prompt settings
read -p "Enter the name of the VM (default is vm): " VM_NAME
VM_NAME=${VM_NAME:-vm}
read -p "Enter the amount of RAM in MB (default is 8192): " RAM_MB
RAM_MB=${RAM_MB:-8192}
read -p "Enter the disk size in GB (default is 100): " DISK_SIZE
DISK_SIZE=${DISK_SIZE:-100}

SSH_PUBKEYS=("$HOME/.ssh"/*.pub)
if [ ${#SSH_PUBKEYS[@]} -eq 0 ]; then
  echo "No .pub files found in ~/.ssh directory."
  exit 1
elif [ ${#SSH_PUBKEYS[@]} -eq 1 ]; then
  SSH_PUBKEY=${SSH_PUBKEYS[0]}
else
  SSH_PUBKEY=$(printf "%s\n" "${SSH_PUBKEYS[@]}" | fzf --prompt="Select a .pub file: ")
fi

if [ -z "$SSH_PUBKEY" ]; then
  echo "No SSH pubkey selected."
  exit 1
fi

# Disk path
VM_DISK="/var/lib/libvirt/images/${VM_NAME}.qcow2"

# Download Virtio Drivers ISO
echo "Downloading Virtio drivers ISO..."
sudo curl -L -o "$VIRTIO_ISO" --etag-save "$VIRTIO_ISO.tmp" --etag-compare "$VIRTIO_ISO.etag" "$VIRTIO_ISO_URL"
sudo mv "$VIRTIO_ISO.tmp" "$VIRTIO_ISO.etag"

# Create autounattend
temp="$(mktemp -d)"

cleanup() {
  sudo umount "$temp/mount" 2> /dev/null
  rm -rf "$temp"
}
trap cleanup EXIT

chmod 0755 "$temp"
mkdir -p "$temp/mount" "$temp/modifications"

# Make virtio disk drivers available to setup
#
# https://learn.microsoft.com/en-us/troubleshoot/windows-client/setup-upgrade-and-drivers/limitations-dollar-sign-winpedriver-dollar-sign
sudo mount -o loop "$VIRTIO_ISO" "$temp/mount"
mkdir "$temp/modifications/\$WinpeDriver\$"
cp -r --no-preserve=mode "$temp/mount/amd64/w11" "$temp/modifications/\$WinpeDriver\$"
sudo umount "$temp/mount"

# Prepare an installation file automatically installs Windows.
#
# Allows ssh authentication with all public keys found in ~/.ssh.
AUTHORIZED_KEYS="$(cat "$SSH_PUBKEY")" envsubst '$USER $AUTHORIZED_KEYS' < autounattend.xml > "$temp/modifications/autounattend.xml"

# Generate bootable ISO.
#
# This ISO contains the autounattend.xml and doesn't require pressing a button
# to start the installation. See:
#  * https://palant.info/2023/02/13/automating-windows-installation-in-a-vm/
sudo mount -o loop "$ISO_PATH" "$temp/mount"

genisoimage \
  -iso-level 4 -rock -udf \
  -disable-deep-relocation \
  -untranslated-filenames \
  -allow-limited-size \
  -no-emul-boot \
  -boot-load-size 8 \
  -eltorito-boot boot/etfsboot.com \
  -eltorito-alt-boot \
  -eltorito-boot efi/microsoft/boot/efisys_noprompt.bin \
  -o "$temp/win.iso" \
  "$temp/mount" "$temp/modifications"

# Create VM Disk
sudo qemu-img create -f qcow2 "$VM_DISK" "${DISK_SIZE}G"

CPU="host-passthrough"
# The CPU is chosen to disable TSX, and features necessary to run Hyper-V inside
# the VM are enabled. See:
#  * https://www.redpill-linpro.com/techblog/2021/04/07/nested-virtualization-hyper-v-in-qemu-kvm.html
#  * https://qemu-project.gitlab.io/qemu/system/qemu-cpu-models.html
# CPU="Broadwell-noTSX-IBRS,-hypervisor,+vmx"

# Define and create the VM using virt-install
sudo virt-install \
  --connect qemu:///system \
  --name "$VM_NAME" \
  --ram "$RAM_MB" \
  --vcpus "$(nproc),cores=$(nproc)" \
  --cpu "$CPU" \
  --os-variant win11 \
  --network network=default,model=virtio \
  --channel type=unix,source.mode=bind,target.type=virtio,target.name=org.qemu.guest_agent.0 \
  --graphics spice \
  --disk path="$VM_DISK",format=qcow2,bus=virtio,size="$DISK_SIZE",boot.order=1 \
  --disk path="$temp/win.iso",device=cdrom,bus=sata,boot.order=2 \
  --disk path="$VIRTIO_ISO",device=cdrom,bus=sata \
  --install bootdev=cdrom \
  --boot uefi,firmware.feature0.name=enrolled-keys,firmware.feature0.enabled=no \
  --noautoconsole # \
  # --features hyperv.synic.state=on \
  # --xml ./features/hyperv/vpindex/@state=on \

# Start the VM
echo "Windows VM setup initiated, click through the installer."
virt-manager --connect qemu:///system --show-domain-console "$VM_NAME"

echo "Waiting for VM to receive an IP."
ip=""
while [ -z "$ip" ]; do
  ip="$(virsh domifaddr "$VM_NAME" | gawk 'match($0, /([[:digit:]\.]+)\//, a) { print a[1] }')"
  sleep 10
  echo -n .
done
echo

echo "Waiting for SSH to become available to continue installation."
while ! ssh -o ConnectTimeout=10 -T "$ip" '$true' &> /dev/null; do
  echo -n .
done
echo

./setup-efw.sh "$VM_NAME"
