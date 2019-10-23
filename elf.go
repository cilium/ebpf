package ebpf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"io"
	"strings"

	"github.com/cilium/ebpf/asm"

	"github.com/pkg/errors"
)

type elfCode struct {
	*elf.File
	symtab *symtab
}

// LoadCollectionSpecFromReader parses an io.ReaderAt that represents an ELF layout
// into a CollectionSpec.
func LoadCollectionSpecFromReader(code io.ReaderAt) (*CollectionSpec, error) {
	f, err := elf.NewFile(code)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	symbols, err := f.Symbols()
	if err != nil {
		return nil, errors.Wrap(err, "load symbols")
	}

	ec := &elfCode{f, newSymtab(symbols)}

	var licenseSection, versionSection *elf.Section
	progSections := make(map[int]*elf.Section)
	relSections := make(map[int]*elf.Section)
	mapSections := make(map[int]*elf.Section)
	for i, sec := range ec.Sections {
		switch {
		case strings.HasPrefix(sec.Name, "license"):
			licenseSection = sec
		case strings.HasPrefix(sec.Name, "version"):
			versionSection = sec
		case strings.HasPrefix(sec.Name, "maps"):
			mapSections[i] = sec
		case sec.Type == elf.SHT_REL:
			if int(sec.Info) >= len(ec.Sections) {
				return nil, errors.Errorf("found relocation section %v for missing section %v", i, sec.Info)
			}

			// Store relocations under the section index of the target
			idx := int(sec.Info)
			if relSections[idx] != nil {
				return nil, errors.Errorf("section %d has multiple relocation sections", idx)
			}
			relSections[idx] = sec
		case sec.Type == elf.SHT_PROGBITS && (sec.Flags&elf.SHF_EXECINSTR) != 0 && sec.Size > 0:
			progSections[i] = sec
		}
	}

	license, err := loadLicense(licenseSection)
	if err != nil {
		return nil, errors.Wrap(err, "load license")
	}

	version, err := loadVersion(versionSection, ec.ByteOrder)
	if err != nil {
		return nil, errors.Wrap(err, "load version")
	}

	maps, err := ec.loadMaps(mapSections)
	if err != nil {
		return nil, errors.Wrap(err, "load maps")
	}

	progs, libs, err := ec.loadPrograms(progSections, relSections, license, version)
	if err != nil {
		return nil, errors.Wrap(err, "load programs")
	}

	if len(libs) > 0 {
		for name, prog := range progs {
			editor := Edit(&prog.Instructions)
			if err := editor.Link(libs...); err != nil {
				return nil, errors.Wrapf(err, "program %s", name)
			}
		}
	}

	return &CollectionSpec{maps, progs}, nil
}

func loadLicense(sec *elf.Section) (string, error) {
	if sec == nil {
		return "", errors.Errorf("missing license section")
	}
	data, err := sec.Data()
	if err != nil {
		return "", errors.Wrapf(err, "section %s", sec.Name)
	}
	return string(bytes.TrimRight(data, "\000")), nil
}

func loadVersion(sec *elf.Section, bo binary.ByteOrder) (uint32, error) {
	if sec == nil {
		return 0, nil
	}

	var version uint32
	err := binary.Read(sec.Open(), bo, &version)
	return version, errors.Wrapf(err, "section %s", sec.Name)
}

func (ec *elfCode) loadPrograms(progSections, relSections map[int]*elf.Section, license string, version uint32) (map[string]*ProgramSpec, []asm.Instructions, error) {
	progs := make(map[string]*ProgramSpec)
	var libs []asm.Instructions
	for idx, prog := range progSections {
		funcSym := ec.symtab.forSectionOffset(idx, 0)
		if funcSym == nil {
			return nil, nil, errors.Errorf("section %v: no label at start", prog.Name)
		}

		var insns asm.Instructions
		offsets, err := insns.Unmarshal(prog.Open(), ec.ByteOrder)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "program %s", funcSym.Name)
		}

		err = assignSymbols(ec.symtab.forSection(idx), offsets, insns)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "program %s", funcSym.Name)
		}

		if rels := relSections[idx]; rels != nil {
			err = ec.applyRelocations(insns, rels, offsets)
			if err != nil {
				return nil, nil, errors.Wrapf(err, "program %s: section %s", funcSym.Name, rels.Name)
			}
		}

		if progType, attachType := getProgType(prog.Name); progType == UnspecifiedProgram {
			// There is no single name we can use for "library" sections,
			// since they may contain multiple functions. We'll decode the
			// labels they contain later on, and then link sections that way.
			libs = append(libs, insns)
		} else {
			progs[funcSym.Name] = &ProgramSpec{
				Name:          funcSym.Name,
				Type:          progType,
				AttachType:    attachType,
				License:       license,
				KernelVersion: version,
				Instructions:  insns,
			}
		}
	}
	return progs, libs, nil
}

func (ec *elfCode) loadMaps(mapSections map[int]*elf.Section) (map[string]*MapSpec, error) {
	maps := make(map[string]*MapSpec)
	for idx, sec := range mapSections {
		// TODO: Iterate symbols
		n := len(ec.symtab.forSection(idx))
		if n == 0 {
			return nil, errors.Errorf("section %v: no symbols", sec.Name)
		}

		data, err := sec.Data()
		if err != nil {
			return nil, err
		}

		if len(data)%n != 0 {
			return nil, errors.Errorf("map descriptors are not of equal size")
		}

		size := len(data) / n
		var ordered []*MapSpec
		for i := 0; i < n; i++ {
			rd := bytes.NewReader(data[i*size : i*size+size])
			mapSym := ec.symtab.forSectionOffset(idx, uint64(i*size))
			if mapSym == nil {
				return nil, errors.Errorf("section %s: missing symbol for map #%d", sec.Name, i)
			}

			name := mapSym.Name
			if maps[name] != nil {
				return nil, errors.Errorf("section %v: map %v already exists", sec.Name, name)
			}

			var spec MapSpec
			var inner uint32
			switch {
			case binary.Read(rd, ec.ByteOrder, &spec.Type) != nil:
				return nil, errors.Errorf("map %v: missing type", name)
			case binary.Read(rd, ec.ByteOrder, &spec.KeySize) != nil:
				return nil, errors.Errorf("map %v: missing key size", name)
			case binary.Read(rd, ec.ByteOrder, &spec.ValueSize) != nil:
				return nil, errors.Errorf("map %v: missing value size", name)
			case binary.Read(rd, ec.ByteOrder, &spec.MaxEntries) != nil:
				return nil, errors.Errorf("map %v: missing max entries", name)
			case binary.Read(rd, ec.ByteOrder, &spec.Flags) != nil:
				return nil, errors.Errorf("map %v: missing flags", name)
			case rd.Len() > 0 && binary.Read(rd, ec.ByteOrder, &inner) != nil:
				return nil, errors.Errorf("map %v: can't read inner map index", name)
			}

			for rd.Len() > 0 {
				b, err := rd.ReadByte()
				if err != nil {
					return nil, err
				}
				if b != 0 {
					return nil, errors.Errorf("map %v: unknown and non-zero fields in definition", name)
				}
			}

			if spec.Type == ArrayOfMaps || spec.Type == HashOfMaps {
				if int(inner) > len(ordered) {
					return nil, errors.Errorf("map %v: invalid inner map index %d", name, inner)
				}

				innerSpec := ordered[int(inner)]
				if innerSpec.InnerMap != nil {
					return nil, errors.Errorf("map %v: can't nest map of map", name)
				}
				spec.InnerMap = innerSpec.Copy()
			}

			maps[name] = &spec
			ordered = append(ordered, &spec)
		}
	}
	return maps, nil
}

func getProgType(v string) (ProgramType, AttachType) {
	types := map[string]ProgramType{
		// From https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/lib/bpf/libbpf.c#n3568
		"socket":         SocketFilter,
		"seccomp":        SocketFilter,
		"kprobe/":        Kprobe,
		"kretprobe/":     Kprobe,
		"tracepoint/":    TracePoint,
		"xdp":            XDP,
		"perf_event":     PerfEvent,
		"sockops":        SockOps,
		"sk_skb":         SkSKB,
		"sk_msg":         SkMsg,
		"lirc_mode2":     LircMode2,
		"flow_dissector": FlowDissector,

		"cgroup_skb/":       CGroupSKB,
		"cgroup/dev":        CGroupDevice,
		"cgroup/skb":        CGroupSKB,
		"cgroup/sock":       CGroupSock,
		"cgroup/post_bind":  CGroupSock,
		"cgroup/bind":       CGroupSockAddr,
		"cgroup/connect":    CGroupSockAddr,
		"cgroup/sendmsg":    CGroupSockAddr,
		"cgroup/recvmsg":    CGroupSockAddr,
		"cgroup/sysctl":     CGroupSysctl,
		"cgroup/getsockopt": CGroupSockopt,
		"cgroup/setsockopt": CGroupSockopt,
		"classifier":        SchedCLS,
		"action":            SchedACT,
	}
	attachTypes := map[string]AttachType{
		"cgroup_skb/ingress":    AttachCGroupInetIngress,
		"cgroup_skb/egress":     AttachCGroupInetEgress,
		"cgroup/sock":           AttachCGroupInetSockCreate,
		"cgroup/post_bind4":     AttachCGroupInet4PostBind,
		"cgroup/post_bind6":     AttachCGroupInet6PostBind,
		"cgroup/dev":            AttachCGroupDevice,
		"sockops":               AttachCGroupSockOps,
		"sk_skb/stream_parser":  AttachSkSKBStreamParser,
		"sk_skb/stream_verdict": AttachSkSKBStreamVerdict,
		"sk_msg":                AttachSkSKBStreamVerdict,
		"lirc_mode2":            AttachLircMode2,
		"flow_dissector":        AttachFlowDissector,
		"cgroup/bind4":          AttachCGroupInet4Bind,
		"cgroup/bind6":          AttachCGroupInet6Bind,
		"cgroup/connect4":       AttachCGroupInet4Connect,
		"cgroup/connect6":       AttachCGroupInet6Connect,
		"cgroup/sendmsg4":       AttachCGroupUDP4Sendmsg,
		"cgroup/sendmsg6":       AttachCGroupUDP6Sendmsg,
		"cgroup/recvmsg4":       AttachCGroupUDP4Recvmsg,
		"cgroup/recvmsg6":       AttachCGroupUDP6Recvmsg,
		"cgroup/sysctl":         AttachCGroupSysctl,
		"cgroup/getsockopt":     AttachCGroupGetsockopt,
		"cgroup/setsockopt":     AttachCGroupSetsockopt,
	}
	attachType := AttachNone
	for k, t := range attachTypes {
		if strings.HasPrefix(v, k) {
			attachType = t
		}
	}

	for k, t := range types {
		if strings.HasPrefix(v, k) {
			return t, attachType
		}
	}
	return UnspecifiedProgram, AttachNone
}

func assignSymbols(symbolOffsets map[uint64]*elf.Symbol, insOffsets map[uint64]int, insns asm.Instructions) error {
	for offset, sym := range symbolOffsets {
		i, ok := insOffsets[offset]
		if !ok {
			return errors.Errorf("symbol %s: no instruction at offset %d", sym.Name, offset)
		}
		insns[i].Symbol = sym.Name
	}
	return nil
}

func (ec *elfCode) applyRelocations(insns asm.Instructions, sec *elf.Section, offsets map[uint64]int) error {
	if sec.Entsize < 16 {
		return errors.New("rls are less than 16 bytes")
	}

	r := sec.Open()
	for off := uint64(0); off < sec.Size; off += sec.Entsize {
		ent := io.LimitReader(r, int64(sec.Entsize))

		var rel elf.Rel64
		if binary.Read(ent, ec.ByteOrder, &rel) != nil {
			return errors.Errorf("can't parse relocation at offset %v", off)
		}

		sym, err := ec.symtab.forRelocation(rel)
		if err != nil {
			return errors.Wrapf(err, "relocation at offset %v", off)
		}

		idx, ok := offsets[rel.Off]
		if !ok {
			return errors.Errorf("symbol %v: invalid instruction offset %x", sym, rel.Off)
		}
		insns[idx].Reference = sym.Name
	}
	return nil
}

type symtab struct {
	Symbols []elf.Symbol
	index   map[int]map[uint64]*elf.Symbol
}

func newSymtab(symbols []elf.Symbol) *symtab {
	index := make(map[int]map[uint64]*elf.Symbol)
	for i, sym := range symbols {
		switch elf.ST_TYPE(sym.Info) {
		case elf.STT_NOTYPE:
			// Older versions of LLVM doesn't tag
			// symbols correctly.
			break
		case elf.STT_OBJECT:
			break
		case elf.STT_FUNC:
			break
		default:
			continue
		}

		if sym.Name == "" {
			continue
		}

		idx := int(sym.Section)
		if _, ok := index[idx]; !ok {
			index[idx] = make(map[uint64]*elf.Symbol)
		}
		index[idx][sym.Value] = &symbols[i]
	}
	return &symtab{
		symbols,
		index,
	}
}

func (st *symtab) forSection(sec int) map[uint64]*elf.Symbol {
	return st.index[sec]
}

func (st *symtab) forSectionOffset(sec int, offset uint64) *elf.Symbol {
	offsets := st.index[sec]
	if offsets == nil {
		return nil
	}
	return offsets[offset]
}

func (st *symtab) forRelocation(rel elf.Rel64) (*elf.Symbol, error) {
	symNo := int(elf.R_SYM64(rel.Info) - 1)
	if symNo >= len(st.Symbols) {
		return nil, errors.Errorf("symbol %v doesnt exist", symNo)
	}
	return &st.Symbols[symNo], nil
}
