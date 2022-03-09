package btf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal"
)

// extInfo contains extended program metadata.
//
// It is indexed per section.
type extInfo struct {
	funcInfos map[string][]bpfFuncInfo
	lineInfos map[string][]bpfLineInfo
	relos     map[string]CORERelos
}

// loadExtInfos parses the .BTF.ext section into its constituent parts.
func loadExtInfos(r io.ReaderAt, bo binary.ByteOrder, strings stringTable) (*extInfo, error) {
	// Open unbuffered section reader. binary.Read() calls io.ReadFull on
	// the header structs, resulting in one syscall per header.
	headerRd := io.NewSectionReader(r, 0, math.MaxInt64)
	extHeader, err := parseBTFExtHeader(headerRd, bo)
	if err != nil {
		return nil, fmt.Errorf("parsing BTF extension header: %w", err)
	}

	coreHeader, err := parseBTFExtCOREHeader(headerRd, bo, extHeader)
	if err != nil {
		return nil, fmt.Errorf("parsing BTF CO-RE header: %w", err)
	}

	buf := internal.NewBufferedSectionReader(r, extHeader.funcInfoStart(), int64(extHeader.FuncInfoLen))
	funcInfos, err := parseFuncInfos(buf, bo, strings)
	if err != nil {
		return nil, fmt.Errorf("parsing BTF function info: %w", err)
	}

	buf = internal.NewBufferedSectionReader(r, extHeader.lineInfoStart(), int64(extHeader.LineInfoLen))
	lineInfos, err := parseLineInfos(buf, bo, strings)
	if err != nil {
		return nil, fmt.Errorf("parsing BTF line info: %w", err)
	}

	relos := make(map[string]CORERelos)
	if coreHeader != nil && coreHeader.COREReloOff > 0 && coreHeader.COREReloLen > 0 {
		buf = internal.NewBufferedSectionReader(r, extHeader.coreReloStart(coreHeader), int64(coreHeader.COREReloLen))
		relos, err = parseCORERelos(buf, bo, strings)
		if err != nil {
			return nil, fmt.Errorf("parsing CO-RE relocation info: %w", err)
		}
	}

	return &extInfo{funcInfos, lineInfos, relos}, nil
}

// btfExtHeader is found at the start of the .BTF.ext section.
type btfExtHeader struct {
	Magic   uint16
	Version uint8
	Flags   uint8

	// HdrLen is larger than the size of struct btfExtHeader when it is
	// immediately followed by a btfExtCOREHeader.
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
func (h *btfExtHeader) coreReloStart(ch *btfExtCOREHeader) int64 {
	return int64(h.HdrLen + ch.COREReloOff)
}

// btfExtCOREHeader is found right after the btfExtHeader when its HdrLen
// field is larger than its size.
type btfExtCOREHeader struct {
	COREReloOff uint32
	COREReloLen uint32
}

// parseBTFExtCOREHeader parses the tail of the .BTF.ext header. If additional
// header bytes are present, extHeader.HdrLen will be larger than the struct,
// indicating the presence of a CO-RE extension header.
func parseBTFExtCOREHeader(r io.Reader, bo binary.ByteOrder, extHeader *btfExtHeader) (*btfExtCOREHeader, error) {
	extHdrSize := int64(binary.Size(&extHeader))
	remainder := int64(extHeader.HdrLen) - extHdrSize

	if remainder == 0 {
		return nil, nil
	}

	var coreHeader btfExtCOREHeader
	if err := binary.Read(r, bo, &coreHeader); err != nil {
		return nil, fmt.Errorf("can't read header: %v", err)
	}

	return &coreHeader, nil
}

type btfExtInfoSec struct {
	SecNameOff uint32
	NumInfo    uint32
}

// parseExtInfoSec parses a btf_ext_info_sec header within .BTF.ext,
// appearing within func_info and line_info sub-sections.
// These headers appear once for each program section in the ELF and are
// followed by one or more func/line_info records for the section.
func parseExtInfoSec(r io.Reader, bo binary.ByteOrder, strings stringTable) (string, *btfExtInfoSec, error) {
	var infoHeader btfExtInfoSec
	if err := binary.Read(r, bo, &infoHeader); err != nil {
		return "", nil, fmt.Errorf("read ext info header: %w", err)
	}

	secName, err := strings.Lookup(infoHeader.SecNameOff)
	if err != nil {
		return "", nil, fmt.Errorf("get section name: %w", err)
	}
	if secName == "" {
		return "", nil, fmt.Errorf("extinfo header refers to empty section name")
	}

	if infoHeader.NumInfo == 0 {
		return "", nil, fmt.Errorf("section %s has zero records", secName)
	}

	return secName, &infoHeader, nil
}

// parseExtInfoRecordSize parses the uint32 at the beginning of a func_infos
// or line_infos segment that describes the length of all extInfoRecords in
// that segment.
func parseExtInfoRecordSize(r io.Reader, bo binary.ByteOrder) (uint32, error) {
	const maxRecordSize = 256

	var recordSize uint32
	if err := binary.Read(r, bo, &recordSize); err != nil {
		return 0, fmt.Errorf("can't read record size: %v", err)
	}

	if recordSize < 4 {
		// Need at least InsnOff worth of bytes per record.
		return 0, errors.New("record size too short")
	}
	if recordSize > maxRecordSize {
		return 0, fmt.Errorf("record size %v exceeds %v", recordSize, maxRecordSize)
	}

	return recordSize, nil
}

// The size of a FuncInfo in BTF wire format.
var FuncInfoSize = uint32(binary.Size(bpfFuncInfo{}))

type FuncInfo struct {
	fn *Func
}

type bpfFuncInfo struct {
	// Instruction offset of the function within an ELF section.
	InsnOff uint32
	TypeID  TypeID
}

func (fi *FuncInfo) Func() *Func {
	return fi.fn
}

// Marshal into the BTF wire format.
//
// The offset is converted from bytes to instructions.
func (fi *FuncInfo) Marshal(w io.Writer, offset uint64) error {
	bfi := bpfFuncInfo{
		InsnOff: uint32(offset / asm.InstructionSize),
		TypeID:  fi.fn.TypeID,
	}
	return binary.Write(w, internal.NativeEndian, &bfi)
}

// parseLineInfos parses a func_info sub-section within .BTF.ext ito a map of
// func infos indexed by section name.
func parseFuncInfos(r io.Reader, bo binary.ByteOrder, strings stringTable) (map[string][]bpfFuncInfo, error) {
	recordSize, err := parseExtInfoRecordSize(r, bo)
	if err != nil {
		return nil, err
	}

	result := make(map[string][]bpfFuncInfo)
	for {
		secName, infoHeader, err := parseExtInfoSec(r, bo, strings)
		if errors.Is(err, io.EOF) {
			return result, nil
		}
		if err != nil {
			return nil, err
		}

		records, err := parseFuncInfoRecords(r, bo, recordSize, infoHeader.NumInfo)
		if err != nil {
			return nil, fmt.Errorf("section %v: %w", secName, err)
		}

		result[secName] = records
	}
}

// parseFuncInfoRecords parses a stream of func_infos into a funcInfos.
// These records appear after a btf_ext_info_sec header in the func_info
// sub-section of .BTF.ext.
func parseFuncInfoRecords(r io.Reader, bo binary.ByteOrder, recordSize uint32, recordNum uint32) ([]bpfFuncInfo, error) {
	var out []bpfFuncInfo
	var fi bpfFuncInfo

	if exp, got := FuncInfoSize, recordSize; exp != got {
		// BTF blob's record size is longer than we know how to parse.
		return nil, fmt.Errorf("expected FuncInfo record size %d, but BTF blob contains %d", exp, got)
	}

	for i := uint32(0); i < recordNum; i++ {
		if err := binary.Read(r, bo, &fi); err != nil {
			return nil, fmt.Errorf("can't read function info: %v", err)
		}

		if fi.InsnOff%asm.InstructionSize != 0 {
			return nil, fmt.Errorf("offset %v is not aligned with instruction size", fi.InsnOff)
		}

		// ELF tracks offset in bytes, the kernel expects raw BPF instructions.
		// Convert as early as possible.
		fi.InsnOff /= asm.InstructionSize

		out = append(out, fi)
	}

	return out, nil
}

var LineInfoSize = uint32(binary.Size(bpfLineInfo{}))

// LineInfo represents the location and contents of a single line of source
// code a BPF ELF was compiled from.
type LineInfo struct {
	fileName   string
	line       string
	lineNumber uint32
	lineColumn uint32

	// TODO: We should get rid of the fields below, but for that we need to be
	// able to write BTF.

	// Instruction offset of the line within its enclosing function, in instructions.
	insnOff     uint32
	fileNameOff uint32
	lineOff     uint32
}

// Constants for the format of bpfLineInfo.LineCol.
const (
	bpfLineShift = 10
	bpfLineMax   = (1 << (32 - bpfLineShift)) - 1
	bpfColumnMax = (1 << bpfLineShift) - 1
)

type bpfLineInfo struct {
	// Instruction offset of the line within the whole instruction stream, in instructions.
	InsnOff     uint32
	FileNameOff uint32
	LineOff     uint32
	LineCol     uint32
}

func (li *LineInfo) FileName() string {
	return li.fileName
}

func (li *LineInfo) Line() string {
	return li.line
}

func (li *LineInfo) LineNumber() uint32 {
	return li.lineNumber
}

func (li *LineInfo) LineColumn() uint32 {
	return li.lineColumn
}

func (li *LineInfo) String() string {
	return li.line
}

// Marshal writes the binary representation of the LineInfo to w.
// The instruction offset is converted from bytes to instructions.
func (li *LineInfo) Marshal(w io.Writer, offset uint64) error {
	if li.lineNumber > bpfLineMax {
		return fmt.Errorf("line %d exceeds %d", li.lineNumber, bpfLineMax)
	}

	if li.lineColumn > bpfColumnMax {
		return fmt.Errorf("column %d exceeds %d", li.lineColumn, bpfColumnMax)
	}

	bli := bpfLineInfo{
		li.insnOff + uint32(offset/asm.InstructionSize),
		li.fileNameOff,
		li.lineOff,
		(li.lineNumber << bpfLineShift) | li.lineColumn,
	}
	return binary.Write(w, internal.NativeEndian, &bli)
}

type LineInfos []LineInfo

// Marshal writes the BTF wire format of the LineInfos to w.
//
// offset is the start of the enclosing function in bytes.
func (li LineInfos) Marshal(w io.Writer, offset uint64) error {
	for _, info := range li {
		if err := info.Marshal(w, offset); err != nil {
			return err
		}
	}

	return nil
}

// parseLineInfos parses a line_info sub-section within .BTF.ext ito a map of
// line infos indexed by section name.
func parseLineInfos(r io.Reader, bo binary.ByteOrder, strings stringTable) (map[string][]bpfLineInfo, error) {
	recordSize, err := parseExtInfoRecordSize(r, bo)
	if err != nil {
		return nil, err
	}

	result := make(map[string][]bpfLineInfo)
	for {
		secName, infoHeader, err := parseExtInfoSec(r, bo, strings)
		if errors.Is(err, io.EOF) {
			return result, nil
		}
		if err != nil {
			return nil, err
		}

		records, err := parseLineInfoRecords(r, bo, recordSize, infoHeader.NumInfo)
		if err != nil {
			return nil, fmt.Errorf("section %v: %w", secName, err)
		}

		result[secName] = records
	}
}

// parseLineInfoRecords parses a stream of line_infos into a lineInfos.
// These records appear after a btf_ext_info_sec header in the line_info
// sub-section of .BTF.ext.
func parseLineInfoRecords(r io.Reader, bo binary.ByteOrder, recordSize uint32, recordNum uint32) ([]bpfLineInfo, error) {
	var out []bpfLineInfo
	var li bpfLineInfo

	if exp, got := uint32(binary.Size(li)), recordSize; exp != got {
		// BTF blob's record size is longer than we know how to parse.
		return nil, fmt.Errorf("expected LineInfo record size %d, but BTF blob contains %d", exp, got)
	}

	for i := uint32(0); i < recordNum; i++ {
		if err := binary.Read(r, bo, &li); err != nil {
			return nil, fmt.Errorf("can't read line info: %v", err)
		}

		if li.InsnOff%asm.InstructionSize != 0 {
			return nil, fmt.Errorf("offset %v is not aligned with instruction size", li.InsnOff)
		}

		// ELF tracks offset in bytes, the kernel expects raw BPF instructions.
		// Convert as early as possible.
		li.InsnOff /= asm.InstructionSize

		out = append(out, li)
	}

	return out, nil
}

// bpfCORERelo matches the kernel's struct bpf_core_relo.
type bpfCORERelo struct {
	InsnOff      uint32
	TypeID       TypeID
	AccessStrOff uint32
	Kind         COREKind
}

type CORERelocation struct {
	insnOff  uint32
	typeID   TypeID
	accessor coreAccessor
	kind     COREKind
}

type CORERelos []CORERelocation

// Offset adds offset to the instruction offset of all CORERelos
// and returns the result.
func (cr CORERelos) Offset(offset uint32) CORERelos {
	var relos CORERelos
	for _, relo := range cr {
		relo.insnOff += offset
		relos = append(relos, relo)
	}
	return relos
}

var extInfoReloSize = binary.Size(bpfCORERelo{})

// parseCORERelos parses a core_relos sub-section within .BTF.ext ito a map of
// CO-RE relocations indexed by section name.
func parseCORERelos(r io.Reader, bo binary.ByteOrder, strings stringTable) (map[string]CORERelos, error) {
	recordSize, err := parseExtInfoRecordSize(r, bo)
	if err != nil {
		return nil, err
	}

	if recordSize != uint32(extInfoReloSize) {
		return nil, fmt.Errorf("expected record size %d, got %d", extInfoReloSize, recordSize)
	}

	result := make(map[string]CORERelos)
	for {
		secName, infoHeader, err := parseExtInfoSec(r, bo, strings)
		if errors.Is(err, io.EOF) {
			return result, nil
		}
		if err != nil {
			return nil, err
		}

		records, err := parseCOREReloRecords(r, bo, recordSize, infoHeader.NumInfo, strings)
		if err != nil {
			return nil, fmt.Errorf("section %v: %w", secName, err)
		}

		result[secName] = records
	}
}

// parseCOREReloRecords parses a stream of CO-RE relocation entries into a
// coreRelos. These records appear after a btf_ext_info_sec header in the
// core_relos sub-section of .BTF.ext.
func parseCOREReloRecords(r io.Reader, bo binary.ByteOrder, recordSize uint32, recordNum uint32, strings stringTable) (CORERelos, error) {
	var out CORERelos

	var relo bpfCORERelo
	for i := uint32(0); i < recordNum; i++ {
		if err := binary.Read(r, bo, &relo); err != nil {
			return nil, fmt.Errorf("can't read CO-RE relocation: %v", err)
		}

		if relo.InsnOff%asm.InstructionSize != 0 {
			return nil, fmt.Errorf("offset %v is not aligned with instruction size", relo.InsnOff)
		}

		accessorStr, err := strings.Lookup(relo.AccessStrOff)
		if err != nil {
			return nil, err
		}

		accessor, err := parseCOREAccessor(accessorStr)
		if err != nil {
			return nil, fmt.Errorf("accessor %q: %s", accessorStr, err)
		}

		out = append(out, CORERelocation{
			relo.InsnOff,
			relo.TypeID,
			accessor,
			relo.Kind,
		})
	}

	return out, nil
}
