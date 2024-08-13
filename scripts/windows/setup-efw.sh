#!/bin/bash
# Install dependencies required by eBPF for Windows.

set -euo pipefail

VM_NAME="$1"

ip=$(virsh domifaddr "$VM_NAME" | gawk 'match($0, /([[:digit:]\.]+)\//, a) { print a[1] }')

if [ -z "$ip" ]; then
  echo "Can't figure out IP address of VM, giving up"
  exit 1
fi

echo "VM IP is $ip"

echo Installing eBPF for Windows dependencies
scp ./*.ps1 "$ip":
ssh -t "$ip" ".\\Setup.ps1"
