#!/usr/bin/env bash

# Version of libbpf to fetch headers from
LIBBPF_VERSION=0.4.0

# The headers we want
headers=(
    bpf_helper_defs.h
    bpf_helpers.h
)

# Fetch libbpf release and store in /tmp
curl -sL "https://github.com/libbpf/libbpf/archive/refs/tags/v${LIBBPF_VERSION}.tar.gz" -o /tmp/libbpf.tar.gz

# Get each header from the libbpf tar.gz and place in the current directory
for header in "${headers[@]}"
do
   tar xf /tmp/libbpf.tar.gz --strip-components=2  libbpf-"$LIBBPF_VERSION"/src/"$header"
done
