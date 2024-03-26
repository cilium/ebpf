<!-- This snippet is automatically included on every page and takes care of automatically highlighting terminology. -->
*[Program]: Instructions that can be loaded and attached to one or more hooks in the Linux kernel.
*[Map]: Shared piece of memory between userspace and an eBPF program loaded into the kernel.
*[Link]: Connection between a Program and a hook/event in the kernel.
*[BTF]: BPF Type Format; a description of all data types present in the Linux kernel an eBPF object.
*[ELF]: Executable and Linkable Format, a container format used for compiled eBPF programs.
*[Spec]: Unrealized blueprint of an eBPF resource, e.g. MapSpec, ProgramSpec, btf.Spec.
*[CollectionSpec]: Bundle of ProgramSpecs, MapSpecs and a btf.Spec. Direct result of loading an eBPF ELF.
*[Collection]: Bundle of Maps and Programs that were loaded into the kernel. Direct result of instantiating (loading into the kernel) a CollectionSpec.
*[bpffs]: Birtual filesystem for 'pinning' references to eBPF resources in an familiar file hierarchy. Usually mounted at /sys/fs/bpf, but many individual instances can be mounted.
*[helper]: A piece of logic provided by the kernel. Read a map value, redirect a packet, etc.
*[kfunc]: An extensible evolution of the BPF helper mechanism. Can be dynamically provided by kernel modules. Not specified in UAPI.
*[XDP]: eXpress Data Path, a high-performance eBPF-powered data path. Only has a receive hook.
*[bpf2go]: Convenience utility to compile eBPF C using clang and generate a Go skeleton.
*[libbpf]: A library for writing kernel- and user space BPF programs in C, developed by the upstream Linux project.
*[qemu]: A popular virtual machine manager.
*[DCO]: Developer Certificate of Origin.
