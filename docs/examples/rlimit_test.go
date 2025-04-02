//go:build linux

package examples

// DocRlimit {
import "github.com/cilium/ebpf/rlimit"

func init() {
	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err)
	}
}

// }
