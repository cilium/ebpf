# How to contribute

Development happens on [GitHub](https://github.com/cilium/ebpf) and contributions in
all forms are welcome. Please take a look at [the architecture](architecture.md) to get
a better understanding of the high-level goals.

## Running the tests

Many of the tests require privileges to set resource limits and load eBPF code.
The easiest way to obtain these is to run the tests with `sudo`.

To test the current package with your local kernel you can simply run:
```
go test -exec sudo ./...
```

To test the current package with a different kernel version you can use the [run-tests.sh] script.
It requires [virtme], qemu and docker to be installed.
Unfortunately virtme is not well maintained at the moment, so we recommend installing
a known working version:

```shell-session
pip3 install https://github.com/amluto/virtme/archive/beb85146cd91de37ae455eccb6ab67c393e6e290.zip
```

Once you have the dependencies you can run all tests on a different kernel:

```shell-session
./run-tests.sh 5.4
```

Or run a subset of tests:

```shell-session
./run-tests.sh 5.4 -run TCX ./link
```

## Regenerating testdata and source code

The library includes some binary artifacts which are used for tests and some
generated source code. Run `make` in the root of the repository to start
this process.

```shell-session
make
```

This requires Docker, as it relies on a standardized build
environment to keep the build output stable.
It is possible to regenerate data using Podman by overriding the `CONTAINER_*`
variables:

```shell-session
make CONTAINER_ENGINE=podman CONTAINER_RUN_ARGS=
```

### Updating kernel dependencies

Syscall bindings and some parameters required to parse ELF sections are derived
from upstream kernel versions. You can update them to the latest version by:

1. Adjusting the `KERNEL_VERSION` variable in `Makefile`
2. Running
    ```shell-session
    make update-kernel-deps
    ```

Finally, bump the tested kernels in `.github/workflows/ci.yml`

## Project permissions

If you'd like to contribute to the library more regularly, one of the
[maintainers][ebpf-lib-maintainers] can add you to the appropriate team or mark
you as a code owner. Please create an issue in the repository.

* [ebpf-go-contributors]
    * Have ["Triage"][permissions] role
    * May be asked to review certain parts of code
    * May be asked to help with certain issues
* [ebpf-go-reviewers]
    * Have ["Write"][permissions] role
    * Can re-run failed CI tasks
    * Can't merge to protected branches
    * Can't create releases
    * May be asked to become CODEOWNERS
* [ebpf-lib-maintainers]
    * Have ["Admin"][permissions] role
    * CODEOWNERS of last resort

[virtme]: https://github.com/amluto/virtme
[run-tests.sh]: https://github.com/cilium/ebpf/blob/main/run-tests.sh
[permissions]: https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/repository-roles-for-an-organization#permissions-for-each-role
[ebpf-go-contributors]: https://github.com/orgs/cilium/teams/ebpf-go-contributors/members
[ebpf-go-reviewers]: https://github.com/orgs/cilium/teams/ebpf-go-reviewers/members
[ebpf-lib-maintainers]: https://github.com/orgs/cilium/teams/ebpf-lib-maintainers/members