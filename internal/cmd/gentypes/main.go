// Program gentypes reads a compressed vmlinux .BTF section and generates
// syscall bindings from it.
//
// Output is written to "types.go".
package main

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/btf"
	"github.com/cilium/ebpf/internal/sys"
)

type syscallRetval int

const (
	retError syscallRetval = iota
	retFd
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("expect location of compressed vmlinux .BTF as argument")
	}

	raw, err := internal.ReadAllCompressed(args[0])
	if err != nil {
		return err
	}

	spec, err := btf.LoadSpecFromReader(bytes.NewReader(raw))
	if err != nil {
		return err
	}

	output, err := generateTypes(spec)
	if err != nil {
		return err
	}

	w, err := os.Create("types.go")
	if err != nil {
		return err
	}
	defer w.Close()

	return internal.WriteFormatted(output, w)
}

func generateTypes(spec *btf.Spec) ([]byte, error) {
	objName := &btf.Array{Nelems: 16, Type: &btf.Int{Encoding: btf.Char, Size: 1}}
	linkID := &btf.Int{Size: 4}
	pointer := &btf.Int{Size: 8}

	// Pre-declare handwritten types sys.ObjName and sys.Pointer so that
	// generated types can refer to them.
	var (
		_ sys.Pointer
		_ sys.ObjName
		_ sys.LinkID
	)

	gf := &btf.GoFormatter{
		Names: map[btf.Type]string{
			objName: "ObjName",
			linkID:  "LinkID",
			pointer: "Pointer",
		},
		Identifier: internal.Identifier,
		EnumIdentifier: func(name, element string) string {
			return element
		},
	}

	w := bytes.NewBuffer(nil)
	w.WriteString(`// Code generated by internal/cmd/gentypes; DO NOT EDIT.

package sys

import (
	"unsafe"
)

`)

	enums := []struct {
		goType string
		cType  string
	}{
		{"Cmd", "bpf_cmd"},
		{"MapType", "bpf_map_type"},
		{"ProgType", "bpf_prog_type"},
		{"AttachType", "bpf_attach_type"},
		{"LinkType", "bpf_link_type"},
		{"StatsType", "bpf_stats_type"},
		{"SkAction", "sk_action"},
		{"StackBuildIdStatus", "bpf_stack_build_id_status"},
		{"FunctionId", "bpf_func_id"},
		{"AdjRoomMode", "bpf_adj_room_mode"},
		{"HdrStartOff", "bpf_hdr_start_off"},
		{"RetCode", "bpf_ret_code"},
		{"XdpAction", "xdp_action"},
	}

	sort.Slice(enums, func(i, j int) bool {
		return enums[i].goType < enums[j].goType
	})

	enumTypes := make(map[string]btf.Type)
	for _, o := range enums {
		fmt.Println("enum", o.goType)

		var t *btf.Enum
		if err := spec.TypeByName(o.cType, &t); err != nil {
			return nil, err
		}

		// Add the enum as a predeclared type so that generated structs
		// refer to the Go types.
		if name := gf.Names[t]; name != "" {
			return nil, fmt.Errorf("type %q is already declared as %s", o.cType, name)
		}
		gf.Names[t] = o.goType
		enumTypes[o.goType] = t

		decl, err := gf.TypeDeclaration(o.goType, t)
		if err != nil {
			return nil, fmt.Errorf("generate %q: %w", o.goType, err)
		}

		w.WriteString(decl)
		w.WriteRune('\n')
	}

	// Assorted structs

	structs := []struct {
		goType  string
		cType   string
		patches []patch
	}{
		{
			"ProgInfo", "bpf_prog_info",
			[]patch{
				replace(objName, "name"),
				replace(pointer, "xlated_prog_insns"),
				replace(pointer, "map_ids"),
			},
		},
		{
			"MapInfo", "bpf_map_info",
			[]patch{replace(objName, "name")},
		},
		{
			"BtfInfo", "bpf_btf_info",
			[]patch{replace(pointer, "btf", "name")},
		},
		{
			"LinkInfo", "bpf_link_info",
			[]patch{
				replace(enumTypes["LinkType"], "type"),
				replace(linkID, "id"),
				name(3, "extra"),
				replaceUnionWithBytes("extra"),
			},
		},
		{"FuncInfo", "bpf_func_info", nil},
		{"LineInfo", "bpf_line_info", nil},
	}

	sort.Slice(structs, func(i, j int) bool {
		return structs[i].goType < structs[j].goType
	})

	for _, s := range structs {
		fmt.Println("struct", s.goType)

		var t *btf.Struct
		if err := spec.TypeByName(s.cType, &t); err != nil {
			return nil, err
		}

		if err := outputPatchedStruct(gf, w, s.goType, t, s.patches); err != nil {
			return nil, fmt.Errorf("output %q: %w", s.goType, err)
		}
	}

	// Attrs

	attrs := []struct {
		goType  string
		ret     syscallRetval
		cType   string
		cmd     string
		patches []patch
	}{
		{
			"MapCreate", retFd, "map_create", "BPF_MAP_CREATE",
			[]patch{
				replace(objName, "map_name"),
				replace(enumTypes["MapType"], "map_type"),
			},
		},
		{
			"MapLookupElem", retError, "map_elem", "BPF_MAP_LOOKUP_ELEM",
			[]patch{choose(2, "value"), replace(pointer, "key", "value")},
		},
		{
			"MapLookupAndDeleteElem", retError, "map_elem", "BPF_MAP_LOOKUP_AND_DELETE_ELEM",
			[]patch{choose(2, "value"), replace(pointer, "key", "value")},
		},
		{
			"MapUpdateElem", retError, "map_elem", "BPF_MAP_UPDATE_ELEM",
			[]patch{choose(2, "value"), replace(pointer, "key", "value")},
		},
		{
			"MapDeleteElem", retError, "map_elem", "BPF_MAP_DELETE_ELEM",
			[]patch{choose(2, "value"), replace(pointer, "key", "value")},
		},
		{
			"MapGetNextKey", retError, "map_elem", "BPF_MAP_GET_NEXT_KEY",
			[]patch{
				choose(2, "next_key"), replace(pointer, "key", "next_key"),
				truncateAfter("next_key"),
			},
		},
		{
			"MapFreeze", retError, "map_elem", "BPF_MAP_FREEZE",
			[]patch{truncateAfter("map_fd")},
		},
		{
			"MapLookupBatch", retError, "map_elem_batch", "BPF_MAP_LOOKUP_BATCH",
			[]patch{replace(pointer, "in_batch", "out_batch", "keys", "values")},
		},
		{
			"MapLookupAndDeleteBatch", retError, "map_elem_batch", "BPF_MAP_LOOKUP_AND_DELETE_BATCH",
			[]patch{replace(pointer, "in_batch", "out_batch", "keys", "values")},
		},
		{
			"MapUpdateBatch", retError, "map_elem_batch", "BPF_MAP_UPDATE_BATCH",
			[]patch{replace(pointer, "in_batch", "out_batch", "keys", "values")},
		},
		{
			"MapDeleteBatch", retError, "map_elem_batch", "BPF_MAP_DELETE_BATCH",
			[]patch{replace(pointer, "in_batch", "out_batch", "keys", "values")},
		},
		{
			"ProgLoad", retFd, "prog_load", "BPF_PROG_LOAD",
			[]patch{
				replace(objName, "prog_name"),
				replace(enumTypes["ProgType"], "prog_type"),
				replace(enumTypes["AttachType"], "expected_attach_type"),
				replace(pointer,
					"insns",
					"license",
					"log_buf",
					"func_info",
					"line_info",
					"fd_array",
					"core_relos",
				),
			},
		},
		{
			"ProgBindMap", retError, "prog_bind_map", "BPF_PROG_BIND_MAP",
			nil,
		},
		{
			"ObjPin", retError, "obj_pin", "BPF_OBJ_PIN",
			[]patch{replace(pointer, "pathname")},
		},
		{
			"ObjGet", retFd, "obj_pin", "BPF_OBJ_GET",
			[]patch{replace(pointer, "pathname")},
		},
		{
			"ProgAttach", retError, "prog_attach", "BPF_PROG_ATTACH",
			nil,
		},
		{
			"ProgDetach", retError, "prog_attach", "BPF_PROG_DETACH",
			[]patch{truncateAfter("attach_type")},
		},
		{
			"ProgRun", retError, "prog_run", "BPF_PROG_TEST_RUN",
			[]patch{replace(pointer, "data_in", "data_out", "ctx_in", "ctx_out")},
		},
		{
			"ProgGetNextId", retError, "obj_next_id", "BPF_PROG_GET_NEXT_ID",
			[]patch{
				choose(0, "start_id"), rename("start_id", "id"),
				truncateAfter("next_id"),
			},
		},
		{
			"MapGetNextId", retError, "obj_next_id", "BPF_MAP_GET_NEXT_ID",
			[]patch{
				choose(0, "start_id"), rename("start_id", "id"),
				truncateAfter("next_id"),
			},
		},
		// These piggy back on the obj_next_id decl, but only support the
		// first field...
		{
			"BtfGetFdById", retFd, "obj_next_id", "BPF_BTF_GET_FD_BY_ID",
			[]patch{choose(0, "start_id"), rename("start_id", "id"), truncateAfter("id")},
		},
		{
			"MapGetFdById", retFd, "obj_next_id", "BPF_MAP_GET_FD_BY_ID",
			[]patch{choose(0, "start_id"), rename("start_id", "id"), truncateAfter("id")},
		},
		{
			"ProgGetFdById", retFd, "obj_next_id", "BPF_PROG_GET_FD_BY_ID",
			[]patch{choose(0, "start_id"), rename("start_id", "id"), truncateAfter("id")},
		},
		{
			"ObjGetInfoByFd", retError, "info_by_fd", "BPF_OBJ_GET_INFO_BY_FD",
			[]patch{replace(pointer, "info")},
		},
		{
			"RawTracepointOpen", retFd, "raw_tracepoint_open", "BPF_RAW_TRACEPOINT_OPEN",
			[]patch{replace(pointer, "name")},
		},
		{
			"BtfLoad", retFd, "btf_load", "BPF_BTF_LOAD",
			[]patch{replace(pointer, "btf", "btf_log_buf")},
		},
		{
			"LinkCreate", retFd, "link_create", "BPF_LINK_CREATE",
			[]patch{replace(enumTypes["AttachType"], "attach_type")},
		},
		{
			"LinkCreateIter", retFd, "link_create", "BPF_LINK_CREATE",
			[]patch{
				chooseNth(4, 1),
				replace(enumTypes["AttachType"], "attach_type"),
				flattenAnon,
				replace(pointer, "iter_info"),
			},
		},
		{
			"LinkCreatePerfEvent", retFd, "link_create", "BPF_LINK_CREATE",
			[]patch{
				chooseNth(4, 2),
				replace(enumTypes["AttachType"], "attach_type"),
				flattenAnon,
			},
		},
		{
			"LinkUpdate", retError, "link_update", "BPF_LINK_UPDATE",
			nil,
		},
		{
			"EnableStats", retFd, "enable_stats", "BPF_ENABLE_STATS",
			nil,
		},
		{
			"IterCreate", retFd, "iter_create", "BPF_ITER_CREATE",
			nil,
		},
	}

	sort.Slice(attrs, func(i, j int) bool {
		return attrs[i].goType < attrs[j].goType
	})

	var bpfAttr *btf.Union
	if err := spec.TypeByName("bpf_attr", &bpfAttr); err != nil {
		return nil, err
	}
	attrTypes, err := splitUnion(bpfAttr, types{
		{"map_create", "map_type"},
		{"map_elem", "map_fd"},
		{"map_elem_batch", "batch"},
		{"prog_load", "prog_type"},
		{"obj_pin", "pathname"},
		{"prog_attach", "target_fd"},
		{"prog_run", "test"},
		{"obj_next_id", ""},
		{"info_by_fd", "info"},
		{"prog_query", "query"},
		{"raw_tracepoint_open", "raw_tracepoint"},
		{"btf_load", "btf"},
		{"task_fd_query", "task_fd_query"},
		{"link_create", "link_create"},
		{"link_update", "link_update"},
		{"link_detach", "link_detach"},
		{"enable_stats", "enable_stats"},
		{"iter_create", "iter_create"},
		{"prog_bind_map", "prog_bind_map"},
	})
	if err != nil {
		return nil, fmt.Errorf("splitting bpf_attr: %w", err)
	}

	for _, s := range attrs {
		fmt.Println("attr", s.goType)

		t := attrTypes[s.cType]
		if t == nil {
			return nil, fmt.Errorf("unknown attr %q", s.cType)
		}

		goAttrType := s.goType + "Attr"
		if err := outputPatchedStruct(gf, w, goAttrType, t, s.patches); err != nil {
			return nil, fmt.Errorf("output %q: %w", goAttrType, err)
		}

		switch s.ret {
		case retError:
			fmt.Fprintf(w, "func %s(attr *%s) error { _, err := BPF(%s, unsafe.Pointer(attr), unsafe.Sizeof(*attr)); return err }\n\n", s.goType, goAttrType, s.cmd)
		case retFd:
			fmt.Fprintf(w, "func %s(attr *%s) (*FD, error) { fd, err := BPF(%s, unsafe.Pointer(attr), unsafe.Sizeof(*attr)); if err != nil { return nil, err }; return NewFD(int(fd)) }\n\n", s.goType, goAttrType, s.cmd)
		}
	}

	// Link info type specific

	linkInfoExtraTypes := []struct {
		goType  string
		cType   string
		patches []patch
	}{
		{"CgroupLinkInfo", "cgroup", []patch{replace(enumTypes["AttachType"], "attach_type")}},
		{"IterLinkInfo", "iter", []patch{replace(pointer, "target_name"), truncateAfter("target_name_len")}},
		{"NetNsLinkInfo", "netns", []patch{replace(enumTypes["AttachType"], "attach_type")}},
		{"RawTracepointLinkInfo", "raw_tracepoint", []patch{replace(pointer, "tp_name")}},
		{"TracingLinkInfo", "tracing", []patch{replace(enumTypes["AttachType"], "attach_type")}},
		{"XDPLinkInfo", "xdp", nil},
	}

	sort.Slice(linkInfoExtraTypes, func(i, j int) bool {
		return linkInfoExtraTypes[i].goType < linkInfoExtraTypes[j].goType
	})

	var bpfLinkInfo *btf.Struct
	if err := spec.TypeByName("bpf_link_info", &bpfLinkInfo); err != nil {
		return nil, err
	}

	member := bpfLinkInfo.Members[len(bpfLinkInfo.Members)-1]
	bpfLinkInfoUnion, ok := member.Type.(*btf.Union)
	if !ok {
		return nil, fmt.Errorf("there is not type-specific union")
	}

	linkInfoTypes, err := splitUnion(bpfLinkInfoUnion, types{
		{"raw_tracepoint", "raw_tracepoint"},
		{"tracing", "tracing"},
		{"cgroup", "cgroup"},
		{"iter", "iter"},
		{"netns", "netns"},
		{"xdp", "xdp"},
	})
	if err != nil {
		return nil, fmt.Errorf("splitting linkInfo: %w", err)
	}

	for _, s := range linkInfoExtraTypes {
		t := linkInfoTypes[s.cType]
		if err := outputPatchedStruct(gf, w, s.goType, t, s.patches); err != nil {
			return nil, fmt.Errorf("output %q: %w", s.goType, err)
		}
	}

	return w.Bytes(), nil
}

func outputPatchedStruct(gf *btf.GoFormatter, w *bytes.Buffer, id string, s *btf.Struct, patches []patch) error {
	s = btf.Copy(s, nil).(*btf.Struct)

	for i, p := range patches {
		if err := p(s); err != nil {
			return fmt.Errorf("patch %d: %w", i, err)
		}
	}

	decl, err := gf.TypeDeclaration(id, s)
	if err != nil {
		return err
	}

	w.WriteString(decl)
	w.WriteString("\n\n")
	return nil
}

type types []struct {
	name                string
	cFieldOrFirstMember string
}

func splitUnion(union *btf.Union, types types) (map[string]*btf.Struct, error) {
	structs := make(map[string]*btf.Struct)

	for i, t := range types {
		member := union.Members[i]
		s, ok := member.Type.(*btf.Struct)
		if !ok {
			return nil, fmt.Errorf("%q: %s is not a struct", t.name, member.Type)
		}

		if member.Name == "" {
			// This is an anonymous struct, check the name of the first member instead.
			if name := s.Members[0].Name; name != t.cFieldOrFirstMember {
				return nil, fmt.Errorf("first field of %q is %q, not %q", t.name, name, t.cFieldOrFirstMember)
			}
		} else if member.Name != t.cFieldOrFirstMember {
			return nil, fmt.Errorf("name for %q is %q, not %q", t.name, member.Name, t.cFieldOrFirstMember)
		}

		structs[t.name] = s
	}

	return structs, nil
}

type patch func(*btf.Struct) error

func modify(fn func(*btf.Member) error, members ...string) patch {
	return func(s *btf.Struct) error {
		want := make(map[string]bool)
		for _, name := range members {
			want[name] = true
		}

		for i, m := range s.Members {
			if want[m.Name] {
				if err := fn(&s.Members[i]); err != nil {
					return err
				}
				delete(want, m.Name)
			}
		}

		if len(want) == 0 {
			return nil
		}

		var missing []string
		for name := range want {
			missing = append(missing, name)
		}
		sort.Strings(missing)

		return fmt.Errorf("missing members: %v", strings.Join(missing, ", "))
	}
}

func modifyNth(fn func(*btf.Member) error, indices ...int) patch {
	return func(s *btf.Struct) error {
		for _, i := range indices {
			if i >= len(s.Members) {
				return fmt.Errorf("index %d is out of bounds", i)
			}

			if err := fn(&s.Members[i]); err != nil {
				return fmt.Errorf("member #%d: %w", i, err)
			}
		}
		return nil
	}
}

func replace(t btf.Type, members ...string) patch {
	return modify(func(m *btf.Member) error {
		m.Type = t
		return nil
	}, members...)
}

func choose(member int, name string) patch {
	return modifyNth(func(m *btf.Member) error {
		union, ok := m.Type.(*btf.Union)
		if !ok {
			return fmt.Errorf("member %d is %s, not a union", member, m.Type)
		}

		for _, um := range union.Members {
			if um.Name == name {
				m.Name = um.Name
				m.Type = um.Type
				return nil
			}
		}

		return fmt.Errorf("%s has no member %q", union, name)
	}, member)
}

func chooseNth(member int, n int) patch {
	return modifyNth(func(m *btf.Member) error {
		union, ok := m.Type.(*btf.Union)
		if !ok {
			return fmt.Errorf("member %d is %s, not a union", member, m.Type)
		}

		if n >= len(union.Members) {
			return fmt.Errorf("member %d is out of bounds", n)
		}

		um := union.Members[n]
		m.Name = um.Name
		m.Type = um.Type
		return nil
	}, member)
}

func flattenAnon(s *btf.Struct) error {
	for i := range s.Members {
		m := &s.Members[i]

		cs, ok := m.Type.(*btf.Struct)
		if !ok || cs.TypeName() != "" {
			continue
		}

		for j := range cs.Members {
			cs.Members[j].OffsetBits += m.OffsetBits
		}

		newMembers := make([]btf.Member, 0, len(s.Members)+len(cs.Members)-1)
		newMembers = append(newMembers, s.Members[:i]...)
		newMembers = append(newMembers, cs.Members...)
		newMembers = append(newMembers, s.Members[i+1:]...)

		s.Members = newMembers
	}

	return nil
}

func truncateAfter(name string) patch {
	return func(s *btf.Struct) error {
		for i, m := range s.Members {
			if m.Name != name {
				continue
			}

			size, err := btf.Sizeof(m.Type)
			if err != nil {
				return err
			}

			s.Members = s.Members[:i+1]
			s.Size = (m.OffsetBits / 8) + uint32(size)
			return nil
		}

		return fmt.Errorf("no member %q", name)
	}
}

func rename(from, to string) patch {
	return func(s *btf.Struct) error {
		for i, m := range s.Members {
			if m.Name == from {
				s.Members[i].Name = to
				return nil
			}
		}
		return fmt.Errorf("no member named %q", from)
	}
}

func name(member int, name string) patch {
	return modifyNth(func(m *btf.Member) error {
		if m.Name != "" {
			return fmt.Errorf("member already has name %q", m.Name)
		}

		m.Name = name
		return nil
	}, member)
}

func replaceUnionWithBytes(name string) patch {
	return func(s *btf.Struct) error {
		for i, m := range s.Members {
			if m.Name != name {
				continue
			}
			if u, ok := m.Type.(*btf.Union); ok {
				s.Members[i] = btf.Member{
					Name: name,
					Type: &btf.Array{
						Type:   &btf.Int{Size: 1},
						Nelems: u.Size,
					},
					OffsetBits:   s.Members[i].OffsetBits,
					BitfieldSize: s.Members[i].BitfieldSize,
				}
				return nil
			}
		}
		return fmt.Errorf("the union name: %s not found", name)
	}
}
