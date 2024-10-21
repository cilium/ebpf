package ebpf

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf/internal/efw"
	"github.com/cilium/ebpf/internal/sys"
)

func loadCollectionFromNativeImage(file string) (*Collection, error) {
	mapFds := make([]efw.FD, 16)
	programFds := make([]efw.FD, 16)
	nMaps, nPrograms, err := efw.EbpfObjectLoadNativeFds(file, mapFds, programFds)
	if errors.Is(err, efw.EBPF_NO_MEMORY) && (nMaps > len(mapFds) || nPrograms > len(programFds)) {
		mapFds = make([]efw.FD, nMaps)
		programFds = make([]efw.FD, nPrograms)

		nMaps, nPrograms, err = efw.EbpfObjectLoadNativeFds(file, mapFds, programFds)
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
