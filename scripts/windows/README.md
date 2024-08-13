# Windows Development Setup

You will need access to a Windows environment to work on ebpf-go for Windows.
This repository contains a script which (mostly) automatically installs a Windows VM.
It then proceeds to install dependencies necessary to compile and install eBPF for Windows.

```shell
./setup.sh path-to-windows.iso
```

Obtain the ISO by choosing "Download Windows 11 Disk Image (ISO)" on the
[download page](https://www.microsoft.com/en-gb/software-download/windows11/)
and then following the instructions.
__Choose "English (United States)" as product language for a fully automated installation.__

## SSH

The setup script adds a public key from `~/.ssh`,
you should be able to simply ssh into the VM by executing `ssh $IP`.

## Requirements

* Only tested with Windows 11
* `libvirt` using qemu backend
* `genisoimage`
* `curl`
