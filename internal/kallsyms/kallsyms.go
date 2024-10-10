package kallsyms

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

var kernelModules struct {
	sync.RWMutex
	// function to kernel module mapping
	kmods map[string]string
}

// KernelModule returns the kernel module, if any, a probe-able function is contained in.
func KernelModule(fn string) (string, error) {
	kernelModules.RLock()
	kmods := kernelModules.kmods
	kernelModules.RUnlock()

	if kmods == nil {
		kernelModules.Lock()
		defer kernelModules.Unlock()
		kmods = kernelModules.kmods
	}

	if kmods != nil {
		return kmods[fn], nil
	}

	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return "", err
	}
	defer f.Close()
	kmods, err = loadKernelModuleMapping(f)
	if err != nil {
		return "", err
	}

	kernelModules.kmods = kmods
	return kmods[fn], nil
}

// FlushKernelModuleCache removes any cached information about function to kernel module mapping.
func FlushKernelModuleCache() {
	kernelModules.Lock()
	defer kernelModules.Unlock()

	kernelModules.kmods = nil
}

var errKsymIsAmbiguous = errors.New("ksym is ambiguous")

func loadKernelModuleMapping(f io.Reader) (map[string]string, error) {
	mods := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := bytes.Fields(scanner.Bytes())
		if len(fields) < 4 {
			continue
		}
		switch string(fields[1]) {
		case "t", "T":
			mods[string(fields[2])] = string(bytes.Trim(fields[3], "[]"))
		default:
			continue
		}
	}
	if scanner.Err() != nil {
		return nil, scanner.Err()
	}
	return mods, nil
}

func LoadSymbolAddresses(symbols map[string]uint64) error {
	if len(symbols) == 0 {
		return nil
	}

	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return err
	}

	if err := loadSymbolAddresses(f, symbols); err != nil {
		return fmt.Errorf("error loading symbol addresses: %w", err)
	}

	return nil
}

func loadSymbolAddresses(f io.Reader, symbols map[string]uint64) error {
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		var (
			addr   uint64
			t      rune
			symbol string
		)

		line := scan.Text()

		_, err := fmt.Sscanf(line, "%x %c %s", &addr, &t, &symbol)
		if err != nil {
			return err
		}
		// Multiple addresses for a symbol have been found. Lets return an error to not confuse any
		// users and handle it the same as libbpf.
		if existingAddr, found := symbols[symbol]; existingAddr != 0 {
			return fmt.Errorf("symbol %s(0x%x): duplicate found at address 0x%x %w",
				symbol, existingAddr, addr, errKsymIsAmbiguous)
		} else if found {
			symbols[symbol] = addr
		}
	}

	if scan.Err() != nil {
		return scan.Err()
	}

	return nil
}
