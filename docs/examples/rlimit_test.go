package examples

// DocRlimit {
import "github.com/cilium/ebpf/rlimit"

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err)
	}
}

// }
