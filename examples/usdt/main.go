//go:build linux
// +build linux

// This program demonstrates how to attach an eBPF program to a userspace tracepoint (USDT).
// The program will be attached to the 'function__entry' marker built in the Python binary.
//
// https://docs.python.org/3/howto/instrumentation.html#available-static-markers
package main

import (
	"bufio"
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ./bpf/usdt.c -- -I../headers

// Event fields data length.
const strsz = 100 + 1

// SDT note info.
type sdtNoteInfo struct {
	location, base, semaphore uint64
	semaphore_offset_ptrace   uint64
	semaphore_offset_refctr   uint64
	bo                        binary.ByteOrder
	path                      string
}

func (n *sdtNoteInfo) String() string {
	return fmt.Sprintf(
		"NOTE\nFile: %s - %s\nLocation %#x\tBase %#x\tSemaphore %#x\t",
		n.path, n.bo, n.location, n.base, n.semaphore,
	)
}

const (
	provider = "python"
	probe    = "function__entry"
)

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Get the process ID to trace.
	pid := flag.Int("pid", 0, "process ID")
	flag.Parse()
	if *pid == 0 {
		flag.Usage()
		os.Exit(1)
	}

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("load objects: %v", err)
	}
	defer objs.Close()

	// Search the SDT note for the given provider and probe.
	note, err := loadNote(*pid, provider, probe)
	if err != nil {
		log.Fatalf("load note: %v", err)
	}

	// Print the found note.
	fmt.Printf("%s\n\n", note.String())

	// Open an ELF binary.
	ex, err := link.OpenExecutable(note.path)
	if err != nil {
		log.Fatalf("open executable: %v", err)
	}

	// Open a Uprobe on the SDT note address and provider path.
	sym := fmt.Sprintf("ebpf_usdt_%s_%s", provider, probe)
	opts := &link.UprobeOptions{
		PID:          *pid,
		Offset:       note.location,
		RefCtrOffset: note.semaphore_offset_refctr,
	}
	u, err := ex.Uprobe(sym, objs.Handler, opts)
	if err != nil {
		if !errors.Is(err, link.ErrNotSupported) {
			log.Fatalf("create uprobe (with ref_ctr_offset): %v", err)
		}

		// Fallback to manual semaphore handling (Kernel 4.20-)
		opts.RefCtrOffset = 0
		u, err = ex.Uprobe(sym, objs.Handler, opts)
		if err != nil {
			log.Fatalf("create uprobe: %v", err)
		}
		if note.semaphore != 0 {
			if err := semUpdate(*pid, note.semaphore_offset_ptrace, note.bo, true); err != nil {
				log.Fatalf("inc semaphore: %v", err)
			}
			defer func() {
				if err := semUpdate(*pid, note.semaphore_offset_ptrace, note.bo, false); err != nil {
					log.Fatalf("dec semaphore: %v", err)
				}
			}()
		}
	}
	defer u.Close()

	// Open a ringbuf reader from userspace RINGBUF map.
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %v", err)
	}
	defer rd.Close()

	// Close the reader when the process receives a signal, which will exit
	// the read loop.
	go func() {
		<-stopper
		if err := rd.Close(); err != nil {
			log.Fatal(err)
		}
	}()

	fmt.Printf("FILENAME\t\t\t\tFUNCTION\n")
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("received signal, exiting..")
				return
			}
			log.Printf("read from reader: %v", err)
			continue
		}

		fmt.Printf(
			"%s\t\t%s\n",
			string(record.RawSample[:strsz]),
			string(record.RawSample[strsz:]),
		)
	}
}

// Read /proc/<pid>/maps and search for the desired note.
//
// Skip reading notes in the Python executable as we know for sure they
// will be provided by a shared object.
func loadNote(pid int, provider, probe string) (*sdtNoteInfo, error) {
	m, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, err
	}
	defer m.Close()

	s := bufio.NewScanner(m)
	seen := make(map[string]struct{})
	for s.Scan() {
		ss := strings.Split(s.Text(), " ")

		path := ss[len(ss)-1]
		if _, ok := seen[path]; ok {
			continue
		}

		addr := strings.Split(ss[0], "-")
		start, err := strconv.ParseUint(addr[0], 16, 64)
		if err != nil {
			return nil, err
		}

		off, err := strconv.ParseUint(ss[2], 16, 64)
		if err != nil {
			return nil, err
		}

		// Ignore errors and continue if not found.
		note, _ := readSDTNote(path, provider, probe)
		if note != nil {
			note.path = path

			if note.semaphore != 0 {
				note.semaphore_offset_ptrace = note.semaphore + start - off
			}

			return note, nil
		}

		seen[path] = struct{}{}
	}

	return nil, fmt.Errorf("probe %s not found in provider %s", probe, provider)
}

// Find SDT note at .note.stapsdt
//
// www.sourceware.org/systemtap/wiki/UserSpaceProbeImplementation
func readSDTNote(path, provider, probe string) (*sdtNoteInfo, error) {
	osf, err := os.Open(path)
	if err != nil {
		// Not an executable or shared object.
		return nil, err
	}

	f, err := elf.NewFile(osf)
	if err != nil {
		// Not an executable or shared object.
		return nil, err
	}
	defer f.Close()

	sec := f.Section(".note.stapsdt")
	if sec == nil {
		return nil, errors.New("SDT note section not found")
	}

	addrsz := 4
	if f.Class == elf.ELFCLASS64 {
		addrsz = 8
	}

	r := sec.Open()
	base := sdtBaseAddr(f)
	for {
		var namesz, descsz int32

		err = binary.Read(r, f.ByteOrder, &namesz)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		err = binary.Read(r, f.ByteOrder, &descsz)
		if err != nil {
			return nil, err
		}

		// skip note type
		_, err := r.Seek(4, io.SeekCurrent)
		if err != nil {
			return nil, err
		}

		// skip note name
		_, err = r.Seek(int64(namesz), io.SeekCurrent)
		if err != nil {
			return nil, err
		}

		align4 := func(n int32) uint64 {
			return (uint64(n) + 4 - 1) / 4 * 4
		}

		desc := make([]byte, align4(descsz))
		err = binary.Read(r, f.ByteOrder, &desc)
		if err != nil {
			return nil, err
		}

		note := sdtNoteInfo{
			location:  f.ByteOrder.Uint64(desc[0:addrsz]),
			base:      f.ByteOrder.Uint64(desc[addrsz : 2*addrsz]),
			semaphore: f.ByteOrder.Uint64(desc[2*addrsz : 3*addrsz]),
			bo:        f.ByteOrder,
		}

		if base != 0 {
			// From the SystemTap wiki about .stapsdt.base:
			//
			// Nothing about this section itself matters, we just use it as a marker to detect
			// prelink address adjustments.
			// Each probe note records the link-time address of the .stapsdt.base section alongside
			// the probe PC address. The decoder compares the base address stored in the note with
			// the .stapsdt.base section's sh_addr.
			// Initially these are the same, but the section header will be adjusted by prelink.
			// So the decoder applies the difference to the probe PC address to get the correct
			// prelinked PC address; the same adjustment is applied to the semaphore address, if any.
			diff := base - note.base
			note.location = offset(f, note.location+diff)
			if note.semaphore != 0 {
				note.semaphore += diff
				note.semaphore_offset_refctr = semOffset(f, note.semaphore)
			}
		}

		idx := 3 * addrsz
		providersz := bytes.IndexByte(desc[idx:], 0)
		pv := string(desc[idx : idx+providersz])

		idx += providersz + 1
		probesz := bytes.IndexByte(desc[idx:], 0)
		pb := string(desc[idx : idx+probesz])

		if provider == pv && probe == pb {
			return &note, nil
		}
	}

	return nil, fmt.Errorf("probe %s not found in provider %s", probe, provider)
}

func offset(f *elf.File, addr uint64) uint64 {
	for _, prog := range f.Progs {
		if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
			continue
		}
		if prog.Vaddr <= addr && addr < (prog.Vaddr+prog.Memsz) {
			return addr - prog.Vaddr + prog.Off
		}
	}
	return addr
}

func sdtBaseAddr(f *elf.File) uint64 {
	sec := f.Section(".stapsdt.base")
	if sec == nil {
		// .stapsdt.base not present
		return 0
	}
	return sec.Addr
}

func semOffset(f *elf.File, addr uint64) uint64 {
	sec := f.Section(".probes")
	if sec == nil {
		// .probes not present
		return addr
	}
	return addr - sec.Addr + sec.Offset
}

func semUpdate(pid int, semaphore uint64, bo binary.ByteOrder, inc bool) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := unix.PtraceAttach(pid); err != nil {
		return err
	}

	for {
		_, err := syscall.Wait4(pid, nil, 0, nil)
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}

	// Number of expected bytes for unsigned short.
	b := 2

	semb := make([]byte, b)
	c, err := unix.PtracePeekData(pid, uintptr(semaphore), semb)
	if err != nil {
		return fmt.Errorf("ptrace peek: %w", err)
	}
	if c != b {
		return fmt.Errorf("ptrace peek: wrong number of bytes read: %d", c)
	}

	sem := bo.Uint16(semb)
	// In normal cases, this should never underflow.
	if inc {
		sem += 1
	} else {
		sem -= 1
	}
	bo.PutUint16(semb, sem)

	c, err = unix.PtracePokeData(pid, uintptr(semaphore), semb)
	if err != nil {
		return fmt.Errorf("ptrace poke: %w", err)
	}
	if c != b {
		return fmt.Errorf("ptrace poke: wrong number of bytes written: %d", c)
	}

	runtime.KeepAlive(semaphore)

	return unix.PtraceDetach(pid)
}
