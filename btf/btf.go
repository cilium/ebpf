package btf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"io"
	"io/ioutil"
	"math"
	"unsafe"

	"github.com/cilium/ebpf/internal"

	"github.com/pkg/errors"
)

const btfMagic = 0xeB9F

// Spec represents decoded BTF.
type Spec struct {
	rawBTF    []byte
	funcInfos map[string]extInfo
	lineInfos map[string]extInfo
}

type btfHeader struct {
	Magic   uint16
	Version uint8
	Flags   uint8
	HdrLen  uint32

	TypeOff   uint32
	TypeLen   uint32
	StringOff uint32
	StringLen uint32
}

// LoadSpecFromELF reads BTF sections from an ELF.
//
// Returns a nil Spec and no error if no BTF was present.
func LoadSpecFromELF(file *elf.File) (*Spec, error) {
	var (
		btfSection    *elf.Section
		btfExtSection *elf.Section
	)

	for _, sec := range file.Sections {
		switch sec.Name {
		case ".BTF":
			btfSection = sec
		case ".BTF.ext":
			btfExtSection = sec
		}
	}

	if btfSection == nil {
		return nil, nil
	}

	var extReader io.ReadSeeker
	if btfExtSection != nil {
		extReader = btfExtSection.Open()
	}

	return LoadSpecFromReader(btfSection.Open(), extReader, file.ByteOrder)
}

// LoadSpecFromReader decodes BTF from a Reader.
//
// btfExt may be nil.
func LoadSpecFromReader(btf, btfExt io.ReadSeeker, bo binary.ByteOrder) (*Spec, error) {
	const expectedMagic = 0xeB9F

	rawBTF, err := ioutil.ReadAll(btf)
	if err != nil {
		return nil, errors.Wrap(err, "can't read BTF")
	}
	if uint64(len(rawBTF)) > math.MaxUint32 {
		return nil, errors.New("BTF exceeds the maximum size")
	}

	rd := bytes.NewReader(rawBTF)

	var header btfHeader
	if err := binary.Read(rd, bo, &header); err != nil {
		return nil, errors.Wrap(err, "can't read header")
	}

	if header.Magic != expectedMagic {
		return nil, errors.Errorf("incorrect magic value %v", header.Magic)
	}

	if header.Version != 1 {
		return nil, errors.Errorf("unexpected version %v", header.Version)
	}

	if header.Flags != 0 {
		return nil, errors.Errorf("unsupported flags %v", header.Flags)
	}

	if int(header.HdrLen) > binary.Size(&header) {
		// TODO: What is the correct thing to do here?
		return nil, errors.New("header is too long")
	}

	if _, err := rd.Seek(int64(header.HdrLen+header.StringOff), io.SeekStart); err != nil {
		return nil, errors.Wrap(err, "can't seek to start of string section")
	}

	strings, err := readStrings(io.LimitReader(rd, int64(header.StringLen)))
	if err != nil {
		return nil, errors.Wrap(err, "can't read type names")
	}

	if _, err := rd.Seek(int64(header.HdrLen+header.TypeOff), io.SeekStart); err != nil {
		return nil, errors.Wrap(err, "can't seek to start of type section")
	}

	// TODO: Make the types available in the Spec
	_, err = readTypes(io.LimitReader(rd, int64(header.TypeLen)), bo)
	if err != nil {
		return nil, errors.Wrap(err, "can't read types")
	}

	var (
		funcInfos = make(map[string]extInfo)
		lineInfos = make(map[string]extInfo)
	)
	if btfExt != nil {
		funcInfos, lineInfos, err = loadExtInfos(btfExt, bo, strings)
		if err != nil {
			return nil, errors.Wrap(err, "can't read ext info")
		}
	}

	return &Spec{
		rawBTF:    rawBTF,
		funcInfos: funcInfos,
		lineInfos: lineInfos,
	}, nil
}

// Program finds the BTF for a specific section.
//
// Length is the number of bytes in the raw BPF instruction stream.
//
// Returns nil if there is no BTF for the given section.
func (s *Spec) Program(name string, length uint64) (*Program, error) {
	if length == 0 {
		return nil, errors.New("length musn't be zero")
	}

	funcInfos, funcOK := s.funcInfos[name]
	lineInfos, lineOK := s.lineInfos[name]

	if !funcOK && !lineOK {
		return nil, nil
	}

	return &Program{s, length, funcInfos, lineInfos}, nil
}

type BTF struct {
	fd *internal.FD
}

func New(spec *Spec) (*BTF, error) {
	attr := &bpfLoadBTFAttr{
		btf:     internal.NewSlicePointer(spec.rawBTF),
		btfSize: uint32(len(spec.rawBTF)),
	}

	fd, err := bpfLoadBTF(attr)
	if err != nil {
		logBuf := make([]byte, 64*1024)
		attr.logBuf = internal.NewSlicePointer(logBuf)
		attr.btfLogSize = uint32(len(logBuf))
		attr.btfLogLevel = 1
		_, logErr := bpfLoadBTF(attr)
		return nil, errors.Wrap(internal.ErrorWithLog(err, logBuf, logErr), "can't load BTF")
	}

	return &BTF{fd}, nil
}

func (btf *BTF) Close() error {
	return btf.fd.Close()
}

func (btf *BTF) FD() int {
	value, err := btf.fd.Value()
	if err != nil {
		return -1
	}

	return int(value)
}

func minimalBTF(bo binary.ByteOrder) []byte {
	const minHeaderLength = 24

	var (
		types struct {
			Integer btfType
			Var     btfType
			btfVar  struct{ Linkage uint32 }
		}
		typLen  = uint32(binary.Size(&types))
		strings = []byte{0, 'a', 0}
		header  = btfHeader{
			Magic:     btfMagic,
			Version:   1,
			HdrLen:    minHeaderLength,
			TypeOff:   0,
			TypeLen:   typLen,
			StringOff: typLen,
			StringLen: uint32(len(strings)),
		}
	)

	// We use a BTF_KIND_VAR here, to make sure that
	// the kernel understands BTF at least as well as we
	// do. BTF_KIND_VAR was introduced ~5.1.
	types.Integer.SetKind(kindPointer)
	types.Var.NameOff = 1
	types.Var.SetKind(kindVar)
	types.Var.SizeType = 1

	buf := new(bytes.Buffer)
	_ = binary.Write(buf, bo, &header)
	_ = binary.Write(buf, bo, &types)
	buf.Write(strings)

	return buf.Bytes()
}

var haveBTF = internal.FeatureTest(func() bool {
	btf := minimalBTF(internal.NativeEndian)
	fd, err := bpfLoadBTF(&bpfLoadBTFAttr{
		btf:     internal.NewSlicePointer(btf),
		btfSize: uint32(len(btf)),
	})
	if err == nil {
		fd.Close()
		return true
	}
	return false
})

// Supported returns true if the kernel has BTF support.
func Supported() bool {
	return haveBTF()
}

type bpfLoadBTFAttr struct {
	btf         internal.Pointer
	logBuf      internal.Pointer
	btfSize     uint32
	btfLogSize  uint32
	btfLogLevel uint32
}

func bpfLoadBTF(attr *bpfLoadBTFAttr) (*internal.FD, error) {
	const _BTFLoad = 18

	fd, err := internal.BPF(_BTFLoad, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	if err != nil {
		return nil, err
	}

	return internal.NewFD(uint32(fd)), nil
}
