package ebpf

import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf/internal/efw"
	"github.com/cilium/ebpf/internal/sys"
)

/*
ebpf_result_t ebpf_object_load_native_fds(

	_In_z_ const char* file_name,
	_Inout_ size_t* count_of_maps,
	_Out_writes_opt_(count_of_maps) fd_t* map_fds,
	_Inout_ size_t* count_of_programs,
	_Out_writes_opt_(count_of_programs) fd_t* program_fds)
*/
var ebpfObjectLoadNativeFds = efw.Module.NewProc("ebpf_object_load_native_fds")

func loadCollectionFromNativeImage(file string) (*Collection, error) {
	fileBytes, err := sys.ByteSliceFromString(file)
	if err != nil {
		return nil, err
	}

	mapFds := make([]efw.FD, 16)
	programFds := make([]efw.FD, 16)
	nMaps := efw.Size(len(mapFds))
	nPrograms := efw.Size(len(programFds))

	err = efw.CallResult(ebpfObjectLoadNativeFds,
		uintptr(unsafe.Pointer(&fileBytes[0])),
		uintptr(unsafe.Pointer(&nMaps)),
		uintptr(unsafe.Pointer(&mapFds[0])),
		uintptr(unsafe.Pointer(&nPrograms)),
		uintptr(unsafe.Pointer(&programFds[0])),
	)
	if errors.Is(err, efw.EBPF_NO_MEMORY) && (nMaps > efw.Size(len(mapFds)) || nPrograms > efw.Size(len(programFds))) {
		mapFds = make([]efw.FD, nMaps)
		programFds = make([]efw.FD, nPrograms)

		err = efw.CallResult(ebpfObjectLoadNativeFds,
			uintptr(unsafe.Pointer(&fileBytes[0])),
			uintptr(unsafe.Pointer(&nMaps)),
			uintptr(unsafe.Pointer(&mapFds[0])),
			uintptr(unsafe.Pointer(&nPrograms)),
			uintptr(unsafe.Pointer(&programFds[0])),
		)
	}
	if err != nil {
		return nil, err
	}

	mapFds = mapFds[:nMaps]
	programFds = programFds[:nPrograms]

	maps := make(map[string]*Map, len(mapFds))
	for _, raw := range mapFds {
		fd, fdErr := sys.NewFD(int(raw))
		if fdErr != nil {
			err = fdErr
			continue
		}

		m, mapErr := newMapFromFD(fd)
		if mapErr != nil {
			_ = fd.Close()
			err = mapErr
			continue
		}

		if m.name == "" {
			err = fmt.Errorf("unnamed map")
			_ = m.Close()
			continue
		}

		// TODO(windows): m.name may be truncated.
		maps[m.name] = m
	}

	programs := make(map[string]*Program, len(programFds))
	for _, raw := range programFds {
		fd, fdErr := sys.NewFD(int(raw))
		if fdErr != nil {
			err = fdErr
			continue
		}

		program, progErr := newProgramFromFD(fd)
		if progErr != nil {
			_ = fd.Close()
			err = progErr
			continue
		}

		if program.name == "" {
			err = fmt.Errorf("unnamed program")
			_ = program.Close()
			continue
		}

		// TODO(windows): program.name may be truncated.
		programs[program.name] = program
	}

	if err != nil {
		for _, m := range maps {
			_ = m.Close()
		}
		for _, p := range programs {
			_ = p.Close()
		}
		return nil, err
	}

	return &Collection{programs, maps}, nil
}
