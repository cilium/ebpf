package ringbuf

import (
	"fmt"
	"testing"
	"time"

	"github.com/cilium/ebpf/internal/testutils"
)

func BenchmarkRawReader(b *testing.B) {
	testutils.SkipOnOldKernel(b, "5.8", "BPF ring buffer")

	bench := func(b *testing.B, batch int, sampleSize int) {
		b.Run(fmt.Sprintf("commit batch %d sample size %d", batch, sampleSize), func(b *testing.B) {
			prog, events := mustOutputSamplesProgN(b, batch, sampleMessage{size: sampleSize})
			rr, err := NewRawReader(events)
			if err != nil {
				b.Fatal(err)
			}
			defer rr.Close()

			b.ResetTimer()
			b.ReportAllocs()

			// Manually track and report read time since the testing framework's
			// calibration doesn't account for BPF prog run time if the timer is
			// stopped during the run, causing it to scale to millions of b.N per run
			// and hanging the benchmark.
			var sysTime, bpfTime, readTime, commitTime time.Duration

			for b.Loop() {
				// PROG_RUN with a repeat value larger than 1 does not have a fast path
				// and costs orders of magnitude more time (~10ms) than a single run
				// would, even with low values (e.g. 2). [mustRunN] was chosen to ensure
				// a stable amount of allocs even though [mustRun] would be much faster.
				startSys := time.Now()
				bpfTime += mustRunN(b, prog, uint32(batch)) * time.Duration(batch)
				sysTime += time.Since(startSys)

				if err := rr.WithLease(func(lease Lease) error {
					for range batch {
						startRead := time.Now()
						data, _, err := lease.ReadSample()
						readTime += time.Since(startRead)

						if len(data) != sampleSize {
							b.Fatal("Expected sample of size", sampleSize, "but got", len(data))
						}
						if err != nil {
							return err
						}
					}

					startCommit := time.Now()
					lease.Commit()
					commitTime += time.Since(startCommit)

					return nil
				}); err != nil {
					b.Fatal(err)
				}
			}

			// Read + commit is the majority of the time spent processing the batch,
			// excluding filling the ring with samples. This can be compared to Read
			// and ReadInto, so report as main metric.
			b.ReportMetric(float64(readTime.Nanoseconds()+commitTime.Nanoseconds())/float64(b.N), "ns/op")
			// Time spent executing the BPF program internally as reported by the
			// kernel, ignoring syscall overhead.
			b.ReportMetric(float64(bpfTime.Nanoseconds())/float64(b.N), "bpf_ns/op")
			// Time spent committing reader position to kernel memory and
			// synchronizing memory.
			b.ReportMetric(float64(commitTime.Nanoseconds())/float64(b.N), "commit_ns/op")
			// Time spent in [Lease.ReadSample], reading the producer position from
			// shared memory.
			b.ReportMetric(float64(readTime.Nanoseconds())/float64(b.N), "read_ns/op")
			// Time spent in the BPF() syscall for filling the ring.
			b.ReportMetric(float64(sysTime.Nanoseconds())/float64(b.N), "sys_ns/op")
		})
	}

	bench(b, 1, 32)
	bench(b, 2, 32)
	bench(b, 10, 32)
	bench(b, 100, 32)
	bench(b, 1000, 32)

	bench(b, 1, 256)
	bench(b, 2, 256)
	bench(b, 10, 256)
	bench(b, 100, 256)
	bench(b, 1000, 256)
}
