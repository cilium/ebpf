package manager

import (
	"debug/elf"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/pkg/errors"
)

type state uint

const (
	reset state = iota
	initialized
	paused
	running

	// MaxEventNameLen - maximum length for a kprobe (or uprobe) event name
	MaxEventNameLen = 64
)

// ConcatErrors - Concatenate 2 errors into one error.
func ConcatErrors(err1, err2 error) error {
	if err1 == nil {
		return err2
	}
	if err2 != nil {
		return errors.Wrap(err1, err2.Error())
	}
	return err1
}

// availableFilterFunctions - cache of the list of available kernel functions.
var availableFilterFunctions []string

func FindFilterFunction(funcName string) (string, error) {
	// Prepare matching pattern
	searchedName, err := regexp.Compile(funcName)
	if err != nil {
		return "", err
	}

	// Cache available filter functions if necessary
	if len(availableFilterFunctions) == 0 {
		funcs, err := ioutil.ReadFile("/sys/kernel/debug/tracing/available_filter_functions")
		if err != nil {
			return "", err
		}
		availableFilterFunctions = strings.Split(string(funcs), "\n")
		for i, name := range availableFilterFunctions {
			splittedName := strings.Split(name, " ")
			name = splittedName[0]
			splittedName = strings.Split(name, "\t")
			name = splittedName[0]
			availableFilterFunctions[i] = name
		}
		sort.Strings(availableFilterFunctions)
	}

	// Match function name
	var potentialMatches []string
	for _, f := range availableFilterFunctions {
		if searchedName.MatchString(f) {
			potentialMatches = append(potentialMatches, f)
		}
		if f == funcName {
			return f, nil
		}
	}
	if len(potentialMatches) > 0 {
		return potentialMatches[0], nil
	}
	return "", nil
}

// cache of the syscall prefix depending on kernel version
var syscallPrefix string

// GetSyscallFnName - Returns the kernel function of the provided syscall, after reading /proc/kallsyms to retrieve
// the list of symbols of the current kernel.
func GetSyscallFnName(name string) (string, error) {
	return GetSyscallFnNameWithSymFile(name, defaultSymFile)
}

// GetSyscallFnNameWithSymFile - Returns the kernel function of the provided syscall, after reading symFile to retrieve
// the list of symbols of the current kernel.
func GetSyscallFnNameWithSymFile(name string, symFile string) (string, error) {
	if symFile == "" {
		symFile = defaultSymFile
	}
	if syscallPrefix == "" {
		syscall, err := getSyscallName("open", symFile)
		if err != nil {
			return "", err
		}
		// copy to avoid memory leak due to go subslice
		// see: https://go101.org/article/memory-leaking.html
		var b strings.Builder
		b.WriteString(syscall)
		syscall = b.String()

		syscallPrefix = strings.TrimSuffix(syscall, "open")
	}

	return syscallPrefix + name, nil
}

const defaultSymFile = "/proc/kallsyms"

// Returns the qualified syscall named by going through '/proc/kallsyms' on the
// system on which its executed. It allows BPF programs that may have been compiled
// for older syscall functions to run on newer kernels
func getSyscallName(name string, symFile string) (string, error) {
	// Get kernel symbols
	syms, err := ioutil.ReadFile(symFile)
	if err != nil {
		return "", err
	}
	return getSyscallFnNameWithKallsyms(name, string(syms))
}

func getSyscallFnNameWithKallsyms(name string, kallsymsContent string) (string, error) {
	var arch string
	switch runtime.GOARCH {
	case "386":
		arch = "ia32"
	case "arm64":
		arch = "arm64"
	default:
		arch = "x64"
	}

	// We should search for new syscall function like "__x64__sys_open"
	// Note the start of word boundary. Should return exactly one string
	regexStr := `(\b__` + arch + `_[Ss]y[sS]_` + name + `\b)`
	fnRegex := regexp.MustCompile(regexStr)

	match := fnRegex.FindAllString(kallsymsContent, -1)
	if len(match) > 0 {
		return match[0], nil
	}

	// If nothing found, search for old syscall function to be sure
	regexStr = `(\b[Ss]y[sS]_` + name + `\b)`
	fnRegex = regexp.MustCompile(regexStr)
	match = fnRegex.FindAllString(kallsymsContent, -1)
	// If we get something like 'sys_open' or 'SyS_open', return
	// either (they have same addr) else, just return original string
	if len(match) > 0 {
		return match[0], nil
	}

	// check for '__' prefixed functions, like '__sys_open'
	regexStr = `(\b__[Ss]y[sS]_` + name + `\b)`
	fnRegex = regexp.MustCompile(regexStr)
	match = fnRegex.FindAllString(kallsymsContent, -1)
	// If we get something like '__sys_open' or '__SyS_open', return
	// either (they have same addr) else, just return original string
	if len(match) > 0 {
		return match[0], nil
	}

	return "", errors.New("could not find a valid syscall name")
}

var safeEventRegexp = regexp.MustCompile("[^a-zA-Z0-9]")

func GenerateEventName(probeType, funcName, UID string, attachPID int) (string, error) {
	eventName := safeEventRegexp.ReplaceAllString(fmt.Sprintf("%s_%s_%s_%d", probeType, funcName, UID, attachPID), "_")

	if len(eventName) > MaxEventNameLen {
		// truncate the function name and UID name to reduce the length of the event
		eventName = safeEventRegexp.ReplaceAllString(fmt.Sprintf("%s_%s_%s_%d", probeType, funcName[0:int(math.Min(10, float64(len(funcName))))], UID[0:int(math.Min(10, float64(len(UID))))], attachPID), "_")
	}
	if len(eventName) > MaxEventNameLen {
		return "", errors.Errorf("event name too long (kernel limit is %d): %s", MaxEventNameLen, eventName)
	}
	return eventName, nil
}

// getKernelGeneratedEventName returns the pattern used by the kernel when a [k|u]probe is loaded without an event name.
// The library doesn't support loading a [k|u]probe with an address directly, so only one pattern applies here.
func getKernelGeneratedEventName(probeType, funcName string) string {
	return fmt.Sprintf("%s_%s_0", probeType, funcName)
}

// ReadKprobeEvents - Returns the content of kprobe_events
func ReadKprobeEvents() (string, error) {
	kprobeEvents, err := ioutil.ReadFile("/sys/kernel/debug/tracing/kprobe_events")
	if err != nil {
		return "", err
	}
	return string(kprobeEvents), nil
}

// EnableKprobeEvent - Writes a new kprobe in kprobe_events with the provided parameters. Call DisableKprobeEvent
// to remove the krpobe.
func EnableKprobeEvent(probeType, funcName, UID, maxactiveStr string, kprobeAttachPID int) (int, error) {
	// Generate event name
	eventName, err := GenerateEventName(probeType, funcName, UID, kprobeAttachPID)
	if err != nil {
		return -1, err
	}

	// Write line to kprobe_events
	kprobeEventsFileName := "/sys/kernel/debug/tracing/kprobe_events"
	f, err := os.OpenFile(kprobeEventsFileName, os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		return -1, errors.Wrap(err, "cannot open kprobe_events")
	}
	defer f.Close()
	cmd := fmt.Sprintf("%s%s:%s %s\n", probeType, maxactiveStr, eventName, funcName)
	if _, err = f.WriteString(cmd); err != nil && !os.IsExist(err) {
		return -1, errors.Wrapf(err, "cannot write %q to kprobe_events", cmd)
	}

	// Retrieve kprobe ID
	kprobeIDFile := fmt.Sprintf("/sys/kernel/debug/tracing/events/kprobes/%s/id", eventName)
	kprobeIDBytes, err := ioutil.ReadFile(kprobeIDFile)
	if err != nil {
		if os.IsNotExist(err) {
			return -1, ErrKprobeIDNotExist
		}
		return -1, errors.Wrap(err, "cannot read kprobe id")
	}
	kprobeID, err := strconv.Atoi(strings.TrimSpace(string(kprobeIDBytes)))
	if err != nil {
		return -1, errors.Wrap(err, "invalid kprobe id: %v")
	}
	return kprobeID, nil
}

// DisableKprobeEvent - Removes a kprobe from kprobe_events
func DisableKprobeEvent(probeType, funcName, UID string, kprobeAttachPID int) error {
	// Generate event name
	eventName, err := GenerateEventName(probeType, funcName, UID, kprobeAttachPID)
	if err != nil {
		return err
	}
	return disableKprobeEvent(eventName)
}

func disableKprobeEvent(eventName string) error {
	// Write line to kprobe_events
	kprobeEventsFileName := "/sys/kernel/debug/tracing/kprobe_events"
	f, err := os.OpenFile(kprobeEventsFileName, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return errors.Wrap(err, "cannot open kprobe_events")
	}
	defer f.Close()
	cmd := fmt.Sprintf("-:%s\n", eventName)
	if _, err = f.WriteString(cmd); err != nil {
		pathErr, ok := err.(*os.PathError)
		if ok && pathErr.Err == syscall.ENOENT {
			// This can happen when for example two modules
			// use the same elf object and both ratecall `Close()`.
			// The second will encounter the error as the
			// probe already has been cleared by the first.
			return nil
		} else {
			return errors.Wrapf(err, "cannot write %q to kprobe_events", cmd)
		}
	}
	return nil
}

// ReadUprobeEvents - Returns the content of uprobe_events
func ReadUprobeEvents() (string, error) {
	uprobeEvents, err := ioutil.ReadFile("/sys/kernel/debug/tracing/uprobe_events")
	if err != nil {
		return "", err
	}
	return string(uprobeEvents), nil
}

// EnableUprobeEvent - Writes a new Uprobe in uprobe_events with the provided parameters. Call DisableUprobeEvent
// to remove the krpobe.
func EnableUprobeEvent(probeType string, funcName, path, UID string, uprobeAttachPID int, offset uint64) (int, error) {
	// Generate event name
	eventName, err := GenerateEventName(probeType, funcName, UID, uprobeAttachPID)
	if err != nil {
		return -1, err
	}

	// Write line to uprobe_events
	uprobeEventsFileName := "/sys/kernel/debug/tracing/uprobe_events"
	f, err := os.OpenFile(uprobeEventsFileName, os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		return -1, errors.Wrap(err, "cannot open uprobe_events")
	}
	defer f.Close()

	cmd := fmt.Sprintf("%s:%s %s:%#x\n", probeType, eventName, path, offset)

	if _, err = f.WriteString(cmd); err != nil && !os.IsExist(err) {
		return -1, errors.Wrapf(err, "cannot write %q to uprobe_events", cmd)
	}

	// Retrieve Uprobe ID
	uprobeIdFile := fmt.Sprintf("/sys/kernel/debug/tracing/events/uprobes/%s/id", eventName)
	uprobeIdBytes, err := ioutil.ReadFile(uprobeIdFile)
	if err != nil {
		if os.IsNotExist(err) {
			return -1, ErrUprobeIDNotExist
		}
		return -1, errors.Wrap(err, "cannot read uprobe id")
	}
	uprobeId, err := strconv.Atoi(strings.TrimSpace(string(uprobeIdBytes)))
	if err != nil {
		return -1, errors.Wrap(err, "invalid uprobe id")
	}

	return uprobeId, nil
}

// OpenAndListSymbols - Opens an elf file and extracts all its symbols
func OpenAndListSymbols(path string) (*elf.File, []elf.Symbol, error) {
	// open elf file
	f, err := elf.Open(path)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "couldn't open elf file %s", path)
	}
	defer f.Close()

	// Loop through all symbols
	syms, errSyms := f.Symbols()
	dynSyms, errDynSyms := f.DynamicSymbols()
	syms = append(syms, dynSyms...)

	if len(syms) == 0 {
		var err error
		if errSyms != nil {
			err = errors.Wrap(err, "failed to list symbols")
		}
		if errDynSyms != nil {
			err = errors.Wrap(err, "failed to list dynamic symbols")
		}
		if err != nil {
			return nil, nil, err
		} else {
			return nil, nil, errors.New("no symbols found")
		}
	}
	return f, syms, nil
}

// SanitizeUprobeAddresses - sanitizes the addresses of the provided symbols
func SanitizeUprobeAddresses(f *elf.File, syms []elf.Symbol) {
	// If the binary is a non-PIE executable, addr must be a virtual address, otherwise it must be an offset relative to
	// the file load address. For executable (ET_EXEC) binaries and shared objects (ET_DYN), translate the virtual
	// address to physical address in the binary file.
	if f.Type == elf.ET_EXEC || f.Type == elf.ET_DYN {
		for i, sym := range syms {
			for _, prog := range f.Progs {
				if prog.Type == elf.PT_LOAD {
					if sym.Value >= prog.Vaddr && sym.Value < (prog.Vaddr + prog.Memsz) {
						syms[i].Value = sym.Value - prog.Vaddr + prog.Off
					}
				}
			}
		}
	}
}

// FindSymbolOffsets - Parses the provided file and returns the offsets of the symbols that match the provided pattern
func FindSymbolOffsets(path string, pattern *regexp.Regexp) ([]elf.Symbol, error) {
	f, syms, err := OpenAndListSymbols(path)
	if err != nil {
		return nil, err
	}

	var matches []elf.Symbol
	for _, sym := range syms {
		if elf.ST_TYPE(sym.Info) == elf.STT_FUNC && pattern.MatchString(sym.Name) {
			matches = append(matches, sym)
		}
	}

	if len(matches) == 0 {
		return nil, ErrSymbolNotFound
	}

	SanitizeUprobeAddresses(f, matches)
	return matches, nil
}

// DisableUprobeEvent - Removes a uprobe from uprobe_events
func DisableUprobeEvent(probeType string, funcName string, UID string, uprobeAttachPID int) error {
	// Generate event name
	eventName, err := GenerateEventName(probeType, funcName, UID, uprobeAttachPID)
	if err != nil {
		return err
	}
	return disableUprobeEvent(eventName)
}

func disableUprobeEvent(eventName string) error {
	// Write uprobe_events line
	uprobeEventsFileName := "/sys/kernel/debug/tracing/uprobe_events"
	f, err := os.OpenFile(uprobeEventsFileName, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return errors.Wrapf(err, "cannot open uprobe_events")
	}
	defer f.Close()
	cmd := fmt.Sprintf("-:%s\n", eventName)
	if _, err = f.WriteString(cmd); err != nil {
		return errors.Wrapf(err, "cannot write %q to uprobe_events", cmd)
	}
	return nil
}

// GetTracepointID - Returns a tracepoint ID from its category and name
func GetTracepointID(category, name string) (int, error) {
	tracepointIDFile := fmt.Sprintf("/sys/kernel/debug/tracing/events/%s/%s/id", category, name)
	tracepointIDBytes, err := ioutil.ReadFile(tracepointIDFile)
	if err != nil {
		return -1, errors.Wrapf(err, "cannot read tracepoint id %q", tracepointIDFile)
	}
	tracepointID, err := strconv.Atoi(strings.TrimSpace(string(tracepointIDBytes)))
	if err != nil {
		return -1, errors.Wrap(err, "invalid tracepoint id")
	}
	return tracepointID, nil
}
