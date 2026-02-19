package btf

import (
	"errors"
	"math"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/unix"
)

// haveBTF attempts to load a BTF blob containing an Int. It should pass on any
// kernel that supports BPF_BTF_LOAD.
var haveBTF = internal.NewFeatureTest("BTF",
	func(opts ...internal.FeatureTestOption) error {
		// 0-length anonymous integer
		o := internal.BuildOptions(opts...)

		err := probeBTF(&Int{}, o.BpffsTokenFd)
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EPERM) {
			return internal.ErrNotSupported
		}
		return err
	},
	"4.18",
)

// haveMapBTF attempts to load a minimal BTF blob containing a Var. It is
// used as a proxy for .bss, .data and .rodata map support, which generally
// come with a Var and Datasec. These were introduced in Linux 5.2.
var haveMapBTF = internal.NewFeatureTest("Map BTF (Var/Datasec)",
	func(opts ...internal.FeatureTestOption) error {
		if err := haveBTF(opts...); err != nil {
			return err
		}

		v := &Var{
			Name: "a",
			Type: &Pointer{(*Void)(nil)},
		}

		o := internal.BuildOptions(opts...)
		err := probeBTF(v, o.BpffsTokenFd)
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EPERM) {
			// Treat both EINVAL and EPERM as not supported: creating the map may still
			// succeed without Btf* attrs.
			return internal.ErrNotSupported
		}
		return err
	}, "5.2")

// haveProgBTF attempts to load a BTF blob containing a Func and FuncProto. It
// is used as a proxy for ext_info (func_info) support, which depends on
// Func(Proto) by definition.
var haveProgBTF = internal.NewFeatureTest("Program BTF (func/line_info)",
	func(opts ...internal.FeatureTestOption) error {
		if err := haveBTF(opts...); err != nil {
			return err
		}

		fn := &Func{
			Name: "a",
			Type: &FuncProto{Return: (*Void)(nil)},
		}

		o := internal.BuildOptions(opts...)
		err := probeBTF(fn, o.BpffsTokenFd)
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EPERM) {
			return internal.ErrNotSupported
		}
		return err
	}, "5.0")

var haveFuncLinkage = internal.NewFeatureTest("BTF func linkage",
	func(opts ...internal.FeatureTestOption) error {
		if err := haveProgBTF(opts...); err != nil {
			return err
		}

		fn := &Func{
			Name:    "a",
			Type:    &FuncProto{Return: (*Void)(nil)},
			Linkage: GlobalFunc,
		}

		o := internal.BuildOptions(opts...)
		err := probeBTF(fn, o.BpffsTokenFd)
		if errors.Is(err, unix.EINVAL) {
			return internal.ErrNotSupported
		}
		return err
	}, "5.6")

var haveDeclTags = internal.NewFeatureTest("BTF decl tags",
	func(opts ...internal.FeatureTestOption) error {
		if err := haveBTF(opts...); err != nil {
			return err
		}

		t := &Typedef{
			Name: "a",
			Type: &Int{},
			Tags: []string{"a"},
		}

		o := internal.BuildOptions(opts...)
		err := probeBTF(t, o.BpffsTokenFd)
		if errors.Is(err, unix.EINVAL) {
			return internal.ErrNotSupported
		}
		return err
	}, "5.16")

var haveTypeTags = internal.NewFeatureTest("BTF type tags",
	func(opts ...internal.FeatureTestOption) error {
		if err := haveBTF(opts...); err != nil {
			return err
		}

		t := &TypeTag{
			Type:  &Int{},
			Value: "a",
		}

		o := internal.BuildOptions(opts...)
		err := probeBTF(t, o.BpffsTokenFd)
		if errors.Is(err, unix.EINVAL) {
			return internal.ErrNotSupported
		}
		return err
	}, "5.17")

var haveEnum64 = internal.NewFeatureTest("ENUM64",
	func(opts ...internal.FeatureTestOption) error {
		if err := haveBTF(opts...); err != nil {
			return err
		}

		enum := &Enum{
			Size: 8,
			Values: []EnumValue{
				{"TEST", math.MaxUint32 + 1},
			},
		}

		o := internal.BuildOptions(opts...)
		err := probeBTF(enum, o.BpffsTokenFd)
		if errors.Is(err, unix.EINVAL) {
			return internal.ErrNotSupported
		}
		return err
	}, "6.0")

func probeBTF(typ Type, tokenFd int32) error {
	b, err := NewBuilder([]Type{typ})
	if err != nil {
		return err
	}

	buf, err := b.Marshal(nil, nil)
	if err != nil {
		return err
	}

	attr := &sys.BtfLoadAttr{
		Btf:     sys.SlicePointer(buf),
		BtfSize: uint32(len(buf)),
	}

	if tokenFd > 0 {
		attr.BtfTokenFd = tokenFd
		attr.BtfFlags |= sys.BPF_F_TOKEN_FD
	}

	fd, err := sys.BtfLoad(attr)
	if err == nil {
		fd.Close()
	}

	return err
}
