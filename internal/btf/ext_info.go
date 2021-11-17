package btf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal"
)

// btfExtHeader is found at the start of the .BTF.ext section.
type btfExtHeader struct {
	Magic   uint16
	Version uint8
	Flags   uint8

	// HdrLen is larger than the size of struct btfExtHeader when it is
	// immediately followed by a btfExtCoreHeader.
	HdrLen uint32

	FuncInfoOff uint32
	FuncInfoLen uint32
	LineInfoOff uint32
	LineInfoLen uint32
}

// parseBTFExtHeader parses the header of the .BTF.ext section.
func parseBTFExtHeader(r io.Reader, bo binary.ByteOrder) (*btfExtHeader, error) {
	var header btfExtHeader
	if err := binary.Read(r, bo, &header); err != nil {
		return nil, fmt.Errorf("can't read header: %v", err)
	}

	if header.Magic != btfMagic {
		return nil, fmt.Errorf("incorrect magic value %v", header.Magic)
	}

	if header.Version != 1 {
		return nil, fmt.Errorf("unexpected version %v", header.Version)
	}

	if header.Flags != 0 {
		return nil, fmt.Errorf("unsupported flags %v", header.Flags)
	}

	if int64(header.HdrLen) < int64(binary.Size(&header)) {
		return nil, fmt.Errorf("header length shorter than btfExtHeader size")
	}

	return &header, nil
}

// funcInfoStart returns the offset from the beginning of the .BTF.ext section
// to the start of its func_info entries.
func (h *btfExtHeader) funcInfoStart() int64 {
	return int64(h.HdrLen + h.FuncInfoOff)
}

// lineInfoStart returns the offset from the beginning of the .BTF.ext section
// to the start of its line_info entries.
func (h *btfExtHeader) lineInfoStart() int64 {
	return int64(h.HdrLen + h.LineInfoOff)
}

// coreReloStart returns the offset from the beginning of the .BTF.ext section
// to the start of its CO-RE relocation entries.
func (h *btfExtHeader) coreReloStart(ch *btfExtCoreHeader) int64 {
	return int64(h.HdrLen + ch.CoreReloOff)
}

// btfExtCoreHeader is found right after the btfExtHeader when its HdrLen
// field is larger than its size.
type btfExtCoreHeader struct {
	CoreReloOff uint32
	CoreReloLen uint32
}

// parseBTFExtCoreHeader parses the tail of the .BTF.ext header. If additional
// header bytes are present, extHeader.HdrLen will be larger than the struct,
// indicating the presence of a CO-RE extension header.
func parseBTFExtCoreHeader(r io.Reader, bo binary.ByteOrder, extHeader *btfExtHeader) (*btfExtCoreHeader, error) {
	extHdrSize := int64(binary.Size(&extHeader))
	remainder := int64(extHeader.HdrLen) - extHdrSize

	if remainder == 0 {
		return nil, nil
	}

	var coreHeader btfExtCoreHeader
	if err := binary.Read(r, bo, &coreHeader); err != nil {
		return nil, fmt.Errorf("can't read header: %v", err)
	}

	return &coreHeader, nil
}

// parseExtInfos parses the .BTF.ext section.
// The resulting maps are keyed by the sections described by the extInfos.
func parseExtInfos(sec *elf.Section, bo binary.ByteOrder, strings stringTable) (funcInfo, lineInfo map[string]extInfo, relos map[string]coreRelos, err error) {
	// Open unbuffered section reader. binary.Read() calls io.ReadFull on
	// the header structs, resulting in one syscall per header.
	r := sec.Open()

	extHeader, err := parseBTFExtHeader(r, bo)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parsing BTF extension header: %w", err)
	}

	coreHeader, err := parseBTFExtCoreHeader(r, bo, extHeader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parsing BTF CO-RE header: %w", err)
	}

	buf := internal.NewBufferedSectionReader(sec, extHeader.funcInfoStart(), int64(extHeader.FuncInfoLen))
	funcInfo, err = parseExtInfo(buf, bo, strings)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("function info: %w", err)
	}

	buf = internal.NewBufferedSectionReader(sec, extHeader.lineInfoStart(), int64(extHeader.LineInfoLen))
	lineInfo, err = parseExtInfo(buf, bo, strings)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("line info: %w", err)
	}

	if coreHeader.CoreReloOff > 0 && coreHeader.CoreReloLen > 0 {
		buf = internal.NewBufferedSectionReader(sec, extHeader.coreReloStart(coreHeader), int64(coreHeader.CoreReloLen))
		relos, err = parseExtInfoRelos(buf, bo, strings)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("CO-RE relocation info: %w", err)
		}
	}

	return funcInfo, lineInfo, relos, nil
}

type btfExtInfoSec struct {
	SecNameOff uint32
	NumInfo    uint32
}

type extInfoRecord struct {
	InsnOff uint64
	Opaque  []byte
}

type extInfo struct {
	byteOrder  binary.ByteOrder
	recordSize uint32
	records    []extInfoRecord
}

func (ei extInfo) append(other extInfo, offset uint64) (extInfo, error) {
	if other.byteOrder != ei.byteOrder {
		return extInfo{}, fmt.Errorf("ext_info byte order mismatch, want %v (got %v)", ei.byteOrder, other.byteOrder)
	}

	if other.recordSize != ei.recordSize {
		return extInfo{}, fmt.Errorf("ext_info record size mismatch, want %d (got %d)", ei.recordSize, other.recordSize)
	}

	records := make([]extInfoRecord, 0, len(ei.records)+len(other.records))
	records = append(records, ei.records...)
	for _, info := range other.records {
		records = append(records, extInfoRecord{
			InsnOff: info.InsnOff + offset,
			Opaque:  info.Opaque,
		})
	}
	return extInfo{ei.byteOrder, ei.recordSize, records}, nil
}

func (ei extInfo) MarshalBinary() ([]byte, error) {
	if ei.byteOrder != internal.NativeEndian {
		return nil, fmt.Errorf("%s is not the native byte order", ei.byteOrder)
	}

	if len(ei.records) == 0 {
		return nil, nil
	}

	buf := bytes.NewBuffer(make([]byte, 0, int(ei.recordSize)*len(ei.records)))
	for _, info := range ei.records {
		// The kernel expects offsets in number of raw bpf instructions,
		// while the ELF tracks it in bytes.
		insnOff := uint32(info.InsnOff / asm.InstructionSize)
		if err := binary.Write(buf, internal.NativeEndian, insnOff); err != nil {
			return nil, fmt.Errorf("can't write instruction offset: %v", err)
		}

		buf.Write(info.Opaque)
	}

	return buf.Bytes(), nil
}

// parseExtInfo parses an ext info sub-section within .BTF.ext ito a map of
// ext info indexed by section name.
func parseExtInfo(r io.Reader, bo binary.ByteOrder, strings stringTable) (map[string]extInfo, error) {
	const maxRecordSize = 256

	var recordSize uint32
	if err := binary.Read(r, bo, &recordSize); err != nil {
		return nil, fmt.Errorf("can't read record size: %v", err)
	}

	if recordSize < 4 {
		// Need at least insnOff
		return nil, errors.New("record size too short")
	}
	if recordSize > maxRecordSize {
		return nil, fmt.Errorf("record size %v exceeds %v", recordSize, maxRecordSize)
	}

	result := make(map[string]extInfo)
	for {
		secName, infoHeader, err := parseExtInfoHeader(r, bo, strings)
		if errors.Is(err, io.EOF) {
			return result, nil
		}

		var records []extInfoRecord
		for i := uint32(0); i < infoHeader.NumInfo; i++ {
			var byteOff uint32
			if err := binary.Read(r, bo, &byteOff); err != nil {
				return nil, fmt.Errorf("section %v: can't read extended info offset: %v", secName, err)
			}

			buf := make([]byte, int(recordSize-4))
			if _, err := io.ReadFull(r, buf); err != nil {
				return nil, fmt.Errorf("section %v: can't read record: %v", secName, err)
			}

			if byteOff%asm.InstructionSize != 0 {
				return nil, fmt.Errorf("section %v: offset %v is not aligned with instruction size", secName, byteOff)
			}

			records = append(records, extInfoRecord{uint64(byteOff), buf})
		}

		result[secName] = extInfo{
			bo,
			recordSize,
			records,
		}
	}
}

// bpfCoreRelo matches the kernel's struct bpf_core_relo.
type bpfCoreRelo struct {
	InsnOff      uint32
	TypeID       TypeID
	AccessStrOff uint32
	Kind         COREKind
}

type coreRelo struct {
	insnOff  uint32
	typeID   TypeID
	accessor coreAccessor
	kind     COREKind
}

type coreRelos []coreRelo

// append two slices of extInfoRelo to each other. The InsnOff of b are adjusted
// by offset.
func (r coreRelos) append(other coreRelos, offset uint64) coreRelos {
	result := make([]coreRelo, 0, len(r)+len(other))
	result = append(result, r...)
	for _, relo := range other {
		relo.insnOff += uint32(offset)
		result = append(result, relo)
	}
	return result
}

var extInfoReloSize = binary.Size(bpfCoreRelo{})

// parseExtInfoRelos parses a core_relos sub-section within .BTF.ext ito a map of
// CO-RE relocations indexed by section name.
func parseExtInfoRelos(r io.Reader, bo binary.ByteOrder, strings stringTable) (map[string]coreRelos, error) {
	var recordSize uint32
	if err := binary.Read(r, bo, &recordSize); err != nil {
		return nil, fmt.Errorf("read record size: %v", err)
	}

	if recordSize != uint32(extInfoReloSize) {
		return nil, fmt.Errorf("expected record size %d, got %d", extInfoReloSize, recordSize)
	}

	result := make(map[string]coreRelos)
	for {
		secName, infoHeader, err := parseExtInfoHeader(r, bo, strings)
		if errors.Is(err, io.EOF) {
			return result, nil
		}

		var relos coreRelos
		for i := uint32(0); i < infoHeader.NumInfo; i++ {
			var relo bpfCoreRelo
			if err := binary.Read(r, bo, &relo); err != nil {
				return nil, fmt.Errorf("section %v: read record: %v", secName, err)
			}

			if relo.InsnOff%asm.InstructionSize != 0 {
				return nil, fmt.Errorf("section %v: offset %v is not aligned with instruction size", secName, relo.InsnOff)
			}

			accessorStr, err := strings.Lookup(relo.AccessStrOff)
			if err != nil {
				return nil, err
			}

			accessor, err := parseCoreAccessor(accessorStr)
			if err != nil {
				return nil, fmt.Errorf("accessor %q: %s", accessorStr, err)
			}

			relos = append(relos, coreRelo{
				relo.InsnOff,
				relo.TypeID,
				accessor,
				relo.Kind,
			})
		}

		result[secName] = relos
	}
}

// parseExtInfoHeader parses a btf_ext_info_sec header within .BTF.ext,
// appearing within func_info and line_info sub-sections.
// These headers appear once for each program section in the ELF and are
// followed by one or more func/line_info records for the section.
func parseExtInfoHeader(r io.Reader, bo binary.ByteOrder, strings stringTable) (string, *btfExtInfoSec, error) {
	var infoHeader btfExtInfoSec
	if err := binary.Read(r, bo, &infoHeader); err != nil {
		return "", nil, fmt.Errorf("read ext info header: %w", err)
	}

	secName, err := strings.Lookup(infoHeader.SecNameOff)
	if err != nil {
		return "", nil, fmt.Errorf("get section name: %w", err)
	}

	if infoHeader.NumInfo == 0 {
		return "", nil, fmt.Errorf("section %s has zero records", secName)
	}

	return secName, &infoHeader, nil
}
