# How to contribute

Development is on [GitHub](https://github.com/cilium/ebpf) and contributions in
the form of pull requests and issues reporting bugs or suggesting new features
are welcome. Please take a look at [the architecture](ARCHITECTURE.md) to get
a better understanding for the high-level goals.

## Adding a new feature

1. [Join](https://ebpf.io/slack) the
[#ebpf-go](https://cilium.slack.com/messages/ebpf-go) channel to discuss your requirements and how the feature can be implemented. The most important part is figuring out how much new exported API is necessary. **The less new API is required the easier it will be to land the feature.**
2. (*optional*) Create a draft PR if you want to discuss the implementation or have hit a problem. It's fine if this doesn't compile or contains debug statements.
3. Create a PR that is ready to merge. This must pass CI and have tests.

## Running the tests

Many of the tests require privileges to set resource limits and load eBPF code.
The easiest way to obtain these is to run the tests with `sudo`.

To test the current package with your local kernel you can simply run:
```
go test -exec sudo  ./...
```

To test the current package with a different kernel version you can use the [run-tests.sh](run-tests.sh) script.
It requires [virtme](https://github.com/amluto/virtme) and qemu to be installed.

Examples:

```bash
# Run all tests on a 5.4 kernel
./run-tests.sh 5.4

# Run a subset of tests:
./run-tests.sh 5.4 ./link
```

# Contributor ladder

If you'd like to contribute to the library more regularly, one of the
[maintainers][ebpf-lib-maintainers] can add you to the appropriate team or mark
you as a code owner. Just create an issue in the repository.

## [ebpf-lib-contributors]

Contributors support the development of the library by writing code, diagnosing
bugs, triaging issues, answering questions, etc.

* Have ["Triage"][permissions] role
* May be asked to review certain parts of code
* May be asked to help with certain issues

## [ebpf-lib-reviewers]

Code owners have contributed a certain feature or are domain experts. They support
development by helping to review code.

* Have ["Write"][permissions] role
* Can't merge to protected branches
* Can't create releases
* May be asked to become CODEOWNERS

## [ebpf-lib-maintainers]

Code owners of last resort and responsible for the overall direction of the
library.

* Have ["Admin"][permissions] role
* Can re-run failed CI tasks
* May be asked to add others to [ebpf-lib-contributors] or CODEOWNERS

[permissions]: https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/repository-roles-for-an-organization#permissions-for-each-role
[ebpf-lib-contributors]: https://github.com/orgs/cilium/teams/ebpf-lib-contributors/members
[ebpf-lib-reviewers]: https://github.com/orgs/cilium/teams/ebpf-lib-reviewers/members
[ebpf-lib-maintainers]: https://github.com/orgs/cilium/teams/ebpf-lib-maintainers/members