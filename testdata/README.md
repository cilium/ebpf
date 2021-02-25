# eBPF ELF testdata

This directory contains ELF test binaries to exercise the library's ELF loader.

## Makefile

Run `make help` to get a list of basic (non-dynamic) make targets.

## Rebuilding ELFs

`make docker all` rebuilds all ELFs in a Dockerized environment.

Avoid committing binaries built outside of the Docker image to prevent
unnecessary diffs on the binaries.

## Debug Shell inside Docker

`make docker-shell` drops the user into a shell inside the builder image
for debugging purposes.
