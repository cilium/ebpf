module github.com/cilium/ebpf

go 1.24.0

require (
	github.com/go-quicktest/qt v1.101.1-0.20240301121107-c6c8733fa1e6
	github.com/google/go-cmp v0.7.0
	github.com/jsimonetti/rtnetlink/v2 v2.0.1
	golang.org/x/sys v0.37.0
)

require (
	github.com/containerd/stargz-snapshotter/estargz v0.16.3 // indirect
	github.com/docker/cli v28.2.2+incompatible // indirect
	github.com/docker/distribution v2.8.3+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.9.3 // indirect
	github.com/google/go-containerregistry v0.20.6 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/rogpeppe/go-internal v1.12.0 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/spf13/cobra v1.9.1 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
	github.com/vbatts/tar-split v0.12.1 // indirect
	golang.org/x/mod v0.29.0 // indirect
	golang.org/x/net v0.46.0 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/tools v0.38.0 // indirect
)

tool (
	github.com/cilium/ebpf/cmd/bpf2go
	github.com/cilium/ebpf/internal/cmd/gentypes
	github.com/google/go-containerregistry/cmd/crane
	golang.org/x/tools/cmd/stringer
)
