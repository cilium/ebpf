# ci-kernels

A collection of kernels used for CI builds.

1. Update kernel versions in [versions.json](versions.json)
2. Commit and make a PR.

You can approximate CI by running `buildx.sh`:

```shell
$ ./buildx.sh 6.1 amd64 vmlinux --tag foo:vmlinux
```

# Updating the builder

The builder image is still built manually.

1. `make image`
2. `make push`
3. Add files, commit and make a PR.
