# `cilium/ebpf` LLVM Builder Image

This is a simple Docker image to provide reproducible eBPF ELF builds across
contributors' workstations. This standardizes on a single environment used to
regenerate e.g. testdata ELFs and does not depend on the toolchain installed
on the host machine.

Additionally, it reduces drift in the bytecode committed to the repository over
time as the same exact clang + llc version is used throughout the development
lifecycle. Only when upgrading or rebuilding the Docker image would changes in
.elf files be expected (assuming the .c files are untouched).

## Building

Building the image requires Docker. Run the build with:

`make build`

This updates the `VERSION` file. Commit it and submit a PR upstream.

### Regeneration Testdata on non-x86 platforms

Before running `make`, ensure [Docker buildx](https://docs.docker.com/buildx/working-with-buildx/)
is enabled. Additionally `QEMU user` and `binfmt` should be installed. On a Debian based distribution
the command to add them is `apt install qemu-user-static binfmt-support`.


## Pushing

After building, push the image to the Docker registry specified in `IMAGE` with:

`make push`
