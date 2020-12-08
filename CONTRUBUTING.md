# How to contribute

Development is on [GitHub](https://github.com/cilium/ebpf) and contributions in
the form of pull requests and issues reporting bugs or suggesting new features
are welcome.

New features must be acompanied by tests. Before starting work on any large
feature, please [join](https://cilium.herokuapp.com/) the
[#libbpf-go](https://cilium.slack.com/messages/libbpf-go) channel on Slack to
discuss the design first.

## Running the tests

Many of the tests require priviliges to set resource limits and load eBPF code.
The easiest way to obtain these is to run the tests with `sudo`:

    sudo go test ./...