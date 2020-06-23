package manager

import (
	"debug/elf"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/pkg/errors"
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
	default:
		arch = "x64"
	}

	// We should search for new syscall function like "__x64__sys_open"
	// Note the start of word boundary. Should return exactly one string
	regexStr := `(\b__` + arch + `_[Ss]y[sS]_` + name + `\b)`
	fnRegex := regexp.MustCompile(regexStr)

	match := fnRegex.FindAllString(kallsymsContent, -1)

	// If nothing found, search for old syscall function to be sure
	if len(match) == 0 {
		newRegexStr := `(\b[Ss]y[sS]_` + name + `\b)`
		fnRegex = regexp.MustCompile(newRegexStr)
		newMatch := fnRegex.FindAllString(kallsymsContent, -1)

		// If we get something like 'sys_open' or 'SyS_open', return
		// either (they have same addr) else, just return original string
		if len(newMatch) >= 1 {
			return newMatch[0], nil
		} else {
			return "", errors.New("could not find a valid syscall name")
		}
	}

	return match[0], nil
}

var safeEventRegexp = regexp.MustCompile("[^a-zA-Z0-9]")

func SanitizeEventName(event string) string {
	return safeEventRegexp.ReplaceAllString(event, "_")
}

// EnableKprobeEvent - Writes a new kprobe in kprobe_events with the provided parameters. Call DisableKprobeEvent
// to remove the krpobe.
func EnableKprobeEvent(probeType, funcName, UID, maxactiveStr string) (int, error) {
	// Generate event name
	eventName := SanitizeEventName(fmt.Sprintf("%s_%s_%s", probeType, funcName, UID))

	// Write line to kprobe_events
	kprobeEventsFileName := "/sys/kernel/debug/tracing/kprobe_events"
	f, err := os.OpenFile(kprobeEventsFileName, os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		return -1, errors.Wrap(err, "cannot open kprobe_events")
	}
	defer f.Close()
	cmd := fmt.Sprintf("%s%s:%s %s\n", probeType, maxactiveStr, eventName, funcName)
	if _, err = f.WriteString(cmd); err != nil {
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
func DisableKprobeEvent(probeType, funcName, UID string) error {
	// Generate event name
	eventName := SanitizeEventName(fmt.Sprintf("%s_%s_%s", probeType, funcName, UID))

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
			return errors.Wrapf(err, "cannot write %q to kprobe_events: %v", cmd)
		}
	}
	return nil
}

// EnableUprobeEvent - Writes a new Uprobe in uprobe_events with the provided parameters. Call DisableUprobeEvent
// to remove the krpobe.
func EnableUprobeEvent(probeType, funcName, path, UID string) (int, error) {
	// Generate event name
	eventName := SanitizeEventName(fmt.Sprintf("%s_%s_%s_%s", probeType, funcName, path, UID))

	// Retrieve dynamic symbol offset
	offset, err := findSymbolOffset(path, funcName)
	if err != nil {
		return -1, errors.Wrapf(err,"couln't find symbol %s in %s", funcName, path)
	}

	// Write line to uprobe_events
	uprobeEventsFileName := "/sys/kernel/debug/tracing/uprobe_events"
	f, err := os.OpenFile(uprobeEventsFileName, os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		return -1, errors.Wrap(err, "cannot open uprobe_events")
	}
	defer f.Close()

	cmd := fmt.Sprintf("%s:%s %s:%#x\n", probeType, eventName, path, offset)

	if _, err = f.WriteString(cmd); err != nil {
		return -1, errors.Wrapf(err, "cannot write %q to uprobe_events", cmd)
	}

	// Retrieve Uprobe ID
	uprobeIdFile := fmt.Sprintf("/sys/kernel/debug/tracing/events/uprobes/%s/id", eventName)
	uprobeIdBytes, err := ioutil.ReadFile(uprobeIdFile)
	if err != nil {
		if os.IsNotExist(err) {
			return -1, ErrUprobeIDNotExist
		}
		return -1, errors.Wrap(err,"cannot read uprobe id")
	}
	uprobeId, err := strconv.Atoi(strings.TrimSpace(string(uprobeIdBytes)))
	if err != nil {
		return -1, errors.Wrap(err, "invalid uprobe id")
	}

	return uprobeId, nil
}

// findSymbolOffset - Parses the provided file to find the offset of the dynamic symbol provided in name
// TODO: add support for library symbols, for some reason they do not show up in the dynamic symbols ("nm -D lib.so" works though)
func findSymbolOffset(path string, name string) (uint64, error) {
	// open elf file
	f, err := elf.Open(path)
	if err != nil {
		return 0, errors.Wrapf(err, "couldn't open elf file %s", path)
	}
	defer f.Close()

	// Loop through all dynamic symbols
	symbols, err := f.DynamicSymbols()
	if err != nil {
		return 0, errors.Wrapf(err, "couldn't list dynamic symbols")
	}
	for _, sym := range symbols {
		if sym.Name == name {
			return sym.Value, nil
		}
	}
	return 0, ErrSymbolNotFound
}

// DisableUprobeEvent - Removes a uprobe from uprobe_events
func DisableUprobeEvent(probeType, funcName, path, UID string) error {
	// Generate event name
	eventName := SanitizeEventName(fmt.Sprintf("%s_%s_%s_%s", probeType, funcName, path, UID))

	// Write uprobe_events line
	uprobeEventsFileName := "/sys/kernel/debug/tracing/uprobe_events"
	f, err := os.OpenFile(uprobeEventsFileName, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return errors.Wrapf(err, "cannot open uprobe_events")
	}
	defer f.Close()
	cmd := fmt.Sprintf("-:%s\n", eventName)
	if _, err = f.WriteString(cmd); err != nil {
		return errors.Wrapf(err, "cannot write %q to uprobe_events: %v", cmd)
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
