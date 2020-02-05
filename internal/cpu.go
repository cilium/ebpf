package internal

import (
	"io/ioutil"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/xerrors"
)

var sysCPU struct {
	once sync.Once
	err  error
	num  int
}

// PossibleCPUs returns the max number of CPUs a system may possibly have.
func PossibleCPUs() (int, error) {
	sysCPU.once.Do(func() {
		sysCPU.num, sysCPU.err = parseCPUs("/sys/devices/system/cpu/possible")
	})

	return sysCPU.num, sysCPU.err
}

// OnlineCPUs returns the number of currently online CPUs.
func OnlineCPUs() (int, error) {
	return parseCPUs("/sys/devices/system/cpu/online")
}

// parseCPUs parses the number of cpus from sysfs,
// in the format of "/sys/devices/system/cpu/{possible,online,..}.
func parseCPUs(path string) (int, error) {
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		return 0, err
	}

	cpus := strings.Trim(string(buf), "\n ")
	n := int(0)
	for _, cpuRange := range strings.Split(cpus, ",") {
		if len(cpuRange) == 0 {
			continue
		}
		rangeOp := strings.SplitN(cpuRange, "-", 2)
		first, err := strconv.ParseUint(rangeOp[0], 10, 32)
		if err != nil {
			return 0, xerrors.Errorf("%s has unknown format: %v", path, err)
		}
		if len(rangeOp) == 1 {
			n++
			continue
		}
		last, err := strconv.ParseUint(rangeOp[1], 10, 32)
		if err != nil {
			return 0, xerrors.Errorf("%s has unknown format: %v", path, err)
		}
		n += int(last - first + 1)
	}
	return n, nil
}
