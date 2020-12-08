# How to contribute

Development is on [GitHub](https://github.com/cilium/ebpf) and contributions in
the form of pull requests and issues reporting bugs or suggesting new features
are welcome.

eBPF is maintained by [Cloudflare](https://www.cloudflare.com) and
[Cilium](https://www.cilium.io). Feel free to
[join](https://cilium.herokuapp.com/) the
[#libbpf-go](https://cilium.slack.com/messages/libbpf-go) channel on Slack.

## Running the tests

Many of the tests require priviliges to set resource limits and load eBPF code.
The easiest way to obtain these is to run the tests with `sudo`:

    sudo go test ./...