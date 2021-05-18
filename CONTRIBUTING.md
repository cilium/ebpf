# How to contribute

Development is on [GitHub](https://github.com/cilium/ebpf) and contributions in
the form of pull requests and issues reporting bugs or suggesting new features
are welcome. Please take a look at [the architecture](ARCHITECTURE.md) to get
a better understanding for the high-level goals.

New features must be accompanied by tests. Before starting work on any large
feature, please [join](https://cilium.herokuapp.com/) the
[#libbpf-go](https://cilium.slack.com/messages/libbpf-go) channel on Slack to
discuss the design first.

When submitting pull requests, consider writing details about what problem you
are solving and why the proposed approach solves that problem in commit messages
and/or pull request description to help future library users and maintainers to
reason about the proposed changes.

## Running the tests

Many of the tests require privileges to set resource limits and load eBPF code.
The easiest way to obtain these is to run the tests with `sudo`:

    sudo go test ./...

## Other platforms

The main development platform that the project targets is `amd64`. However running
the code and the examples should not be hard on any platform supported by `go` and
`docker`. Here are some hints for `arm64`, adding other platforms should be similar.
The suggested approach will always use `amd64` build tools, but allow to cross-build
and use them with an emulation.

#### Ubuntu `linux/arm64`

 * Install a version of [Docker CE](https://docs.docker.com/engine/install/ubuntu/)
   which is newer than 19.03. Make sure that [Docker Builds](https://docs.docker.com/buildx/working-with-buildx/)
   is enabled by checking the output of `docker info| grep buildx`
 * Make sure `QEMU user` and `binfmt` are installed: `apt install -y qemu-user-static binfmt-support`
 * Check that the BuildKit builder supports the `linux/amd64` platform:
```shell
$ docker buildx ls
NAME/NODE DRIVER/ENDPOINT STATUS  PLATFORMS
default * docker
  default default         running linux/arm64, linux/amd64, linux/riscv64, linux/ppc64le, linux/s390x, linux/386
```

#### OSX `darwin/arm64`

Everything that's needed is to use Docker Desktop version compatible with `darwin/arm64`.
It comes already pre-configured with everything needed to build the project. It is not
possible to run the tests on it though, as Darwin kernel still do not support eBPF.
