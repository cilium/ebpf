Examples
--------

To the build the examples folder you'll need to pull the linux repository. Once it's on your host
you can build this folder:

```sh
make kernel_src=/path/to/kernel/src
```

It is possible to build bpf programs without downloading the entire kernel, but you'll have to go
hunting through the kernel source code for the particulars you need. It's much easier to just download it.