//go:build unix

package testutils

import (
	"fmt"
	"math"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/cilium/ebpf/internal/platform"
	"github.com/cilium/ebpf/internal/unix"
)

// The logic in this file implements running tests with BPF tokens. The process
// works as follows:
//
//  1. A test or subtest calls [RunWithToken], which runs the test binary as a
//     subprocess in its own user and mount namespace.
//  2. Child and parent work together to set up a bpffs with the desired
//     delegated permissions.
//  3. The child mounts the token bpffs, drops capabilities and re-execs itself.
//
// The [setupUserNS] environment variable is set if child-side setup needs to
// take place. The [testUserNS] environment variable is set by the child before
// re-execing itself to signal that setup is done and the function under test
// can be run.

const (
	// testUserNS being set indicates that setup is done and the test can be run.
	// Set in the child process after user namespace setup is done and before
	// re-execing itself.
	testUserNS = "TEST_USERNS"

	readyMarker = byte(0x60)

	// File descriptors passed to [exec.Cmd.ExtraFiles] start at fd 3, being the
	// to-parent socket in the child process.
	toParentFd = 3
)

func init() {
	// Before running any tests, check if we're a child process that needs to do
	// user namespace setup and re-exec.
	_, ok := os.LookupEnv(setupUserNS)
	if !ok {
		return
	}
	os.Unsetenv(setupUserNS)

	// Note: this function never returns; it ends with a call to exec().
	setupChildExec()
}

// RunWithToken runs fn as a subtest as an unprivileged, user-namespaced
// subprocess with only the given BPF permissions delegated to it. The subtest
// carries the given name.
//
// The subprocess retains CAP_BPF and CAP_DAC_READ_SEARCH to make BPF() syscalls
// with a token and read files owned by the test user.
//
//	testutils.RunWithToken(t, "foo", testutils.Delegated{
//		Cmds: []sys.Cmd{sys.BPF_MAP_CREATE},
//		Maps: []sys.MapType{sys.BPF_MAP_TYPE_HASH},
//	}, func(t *testing.T) {
//		_, err := newMap(t, hashMapSpec, nil)
//		qt.Assert(t, qt.IsNil(err))
//	})
//
// Only works on Linux 6.9 and later.
func RunWithToken(t *testing.T, name string, delegated Delegated, fn func(t *testing.T)) {
	t.Helper()

	if !platform.IsLinux {
		t.Skip("BPF tokens only work on Linux")
	}

	SkipOnOldKernel(t, "6.9", "BPF_TOKEN_CREATE")

	t.Run(name, func(t *testing.T) {
		// User namespace setup done. Run the function under test and end the test.
		if _, ok := os.LookupEnv(testUserNS); ok {
			fn(t)
			return
		}

		// Execute the parent side of the test, which will spawn the child process
		// and wait for it to finish.
		runSubprocess(t, delegated)
	})
}

func runSubprocess(t *testing.T, delegated Delegated) {
	t.Helper()

	args := []string{
		// Re-run only the exact test and subtest.
		splitTestRun(t),
		// Run the subprocess in test2json mode so all stdout lines belonging to
		// the test framework are prefixed with a marker byte (0x16 or ^V in caret
		// notation).
		"-test.v=test2json",
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("get executable path: %v", err)
	}

	cmd := exec.CommandContext(t.Context(), exe, args...)

	// Signal to the child process that it needs to do user namespace setup.
	cmd.Env = append(cmd.Environ(), setupUserNS+"=true")

	stdout := newt2jParser(t, os.Stdout)
	cmd.Stdout = stdout
	cmd.Stderr = os.Stderr

	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("create socket pair: %v", err)
	}
	toChild := pair[0]
	defer unix.Close(toChild)

	toParent := os.NewFile(uintptr(pair[1]), "child-to-parent-socket")
	defer toParent.Close()

	cmd.ExtraFiles = []*os.File{toParent}
	cmd.SysProcAttr = &unix.SysProcAttr{
		Cloneflags:  unix.CLONE_NEWUSER | unix.CLONE_NEWNS,
		AmbientCaps: []uintptr{uintptr(CAP_SYS_ADMIN), uintptr(CAP_DAC_READ_SEARCH), uintptr(CAP_BPF)},
		UidMappings: mapUID(),
		GidMappings: mapGID(),
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("start child process: %v", err)
	}

	// Explicitly close the parent's copy of the to-parent socket, so that the
	// child can detect when the parent process has exited and avoid hanging if
	// the parent is killed.
	if err := toParent.Close(); err != nil {
		t.Fatalf("close child-to-parent socket in parent: %v", err)
	}

	if err := setupParent(toChild, delegated); err != nil {
		// Clean up child before failing the test to avoid orphaned processes.
		_ = cmd.Process.Kill()
		_ = cmd.Wait()

		t.Fatalf("parent setup: %v", err)
	}

	if err := cmd.Wait(); err != nil && !stdout.failed {
		t.Fatalf("child process exited with error: %v", err)
	}

	stdout.Apply()
}

// splitTestRun returns the '-test.run' argument needed to re-run the current
// test as a child process. 'go test' assigns specific meaning to the '/'
// separator in test names, so each individual part needs to be wrapped as a
// regex matching the exact (sub)test.
//
// For example, if the current test is "TestFoo/bar/baz", the returned argument
// will be:
//
//	-test.run=^TestFoo$/^bar$/^baz$
func splitTestRun(tb testing.TB) string {
	tb.Helper()

	parts := strings.Split(tb.Name(), "/")
	for i, part := range parts {
		parts[i] = "^" + regexp.QuoteMeta(part) + "$"
	}
	return "-test.run=" + strings.Join(parts, "/")
}

// mapUID returns a list of UID mappings for the user namespace. It includes the
// current UID and, if running with sudo, the SUDO_UID. This allows the child
// process to have the same permissions as the parent process in the user
// namespace.
func mapUID() []syscall.SysProcIDMap {
	uids := []int{os.Getuid()}
	if suid, _ := strconv.Atoi(os.Getenv("SUDO_UID")); suid != 0 && !slices.Contains(uids, suid) {
		uids = append(uids, suid)
	}

	var umap []syscall.SysProcIDMap
	for _, uid := range uids {
		umap = append(umap, syscall.SysProcIDMap{
			ContainerID: uid,
			HostID:      uid,
			Size:        1,
		})
	}

	return umap
}

// mapGID is like [mapUID] but for GIDs.
func mapGID() []syscall.SysProcIDMap {
	gids := []int{os.Getgid()}
	if sgid, _ := strconv.Atoi(os.Getenv("SUDO_GID")); sgid != 0 && !slices.Contains(gids, sgid) {
		gids = append(gids, sgid)
	}

	var gmap []syscall.SysProcIDMap
	for _, gid := range gids {
		gmap = append(gmap, syscall.SysProcIDMap{
			ContainerID: gid,
			HostID:      gid,
			Size:        1,
		})
	}

	return gmap
}

// setupParent performs the parent-side setup for a token-scoped test. It
// receives the bpffs file descriptor from the child, configures it with the
// delegated permissions and signals the child to continue.
func setupParent(toChild int, delegated Delegated) error {
	bpffs, err := receiveFD(toChild)
	if err != nil {
		return fmt.Errorf("receive bpffs file descriptor from child: %w", err)
	}
	defer unix.Close(bpffs)

	if err := configureDelegated(bpffs, delegated); err != nil {
		return fmt.Errorf("configure delegated permissions on bpffs: %w", err)
	}

	if err := sendReady(toChild); err != nil {
		return fmt.Errorf("send ready signal to child: %w", err)
	}

	return nil
}

// setupChildExec does the child-side setup for a token-scoped test and re-execs
// the test binary. The function never returns.
func setupChildExec() {
	// Create a new bpffs file system context.
	bpffsCtx, err := unix.Fsopen("bpf", unix.FSOPEN_CLOEXEC)
	if err != nil {
		panicf("create bpffs context: %v", err)
	}

	// Send the bpffs fd to the parent process so it can delegate permissions to
	// it.
	if err := sendFD(toParentFd, bpffsCtx); err != nil {
		panicf("send bpffs fd to parent: %v", err)
	}

	// Wait for the parent's ready signal delegation is done.
	if err := waitReady(toParentFd); err != nil {
		panicf("wait for parent's reply: %v", err)
	}

	if err := unix.Close(toParentFd); err != nil {
		panicf("close child socket: %v", err)
	}

	// Turn the filesystem context into an anonymous mount.
	bpffsMnt, err := unix.Fsmount(bpffsCtx, unix.FSMOUNT_CLOEXEC, 0)
	if err != nil {
		panicf("mount bpffs: %v", err)
	}

	if err := unix.Close(bpffsCtx); err != nil {
		panicf("close bpffs context: %v", err)
	}

	// Move the detached mount to /sys/fs/bpf, the default location.
	if err := unix.MoveMount(bpffsMnt, "", unix.AT_FDCWD, "/sys/fs/bpf", unix.MOVE_MOUNT_F_EMPTY_PATH); err != nil {
		panicf("move mount: %v", err)
	}

	if err := unix.Close(bpffsMnt); err != nil {
		panicf("close bpffs mount fd: %v", err)
	}

	// Drop all but the following capabilities:
	//
	//  - CAP_BPF for making BPF() syscalls with a token
	//  - CAP_DAC_READ_SEARCH for reading files owned by the user running the test,
	//    as we'll be `nobody` in the user namespace.
	const caps = (uint64(1) << CAP_BPF) | (uint64(1) << CAP_DAC_READ_SEARCH)
	if err := capset(capUserData{caps, caps, caps}); err != nil {
		panicf("drop capabilities in child: %v", err)
	}

	// Setup done, re-exec and signal the child to run the function under test.
	if err := os.Setenv(testUserNS, "true"); err != nil {
		panicf("set test environment variable: %v", err)
	}

	if err := syscall.Exec(os.Args[0], os.Args, os.Environ()); err != nil {
		panicf("re-exec child process: %v", err)
	}
}

// sendFD sends fd over sock.
func sendFD(sock, fd int) error {
	// According to the man pages, one byte of non-ancillary data must be sent
	// (and received) along with the fd.
	if err := unix.Sendmsg(sock, []byte{0}, unix.UnixRights(fd), nil, 0); err != nil {
		return fmt.Errorf("send fd to parent: %w", err)
	}

	return nil
}

// receiveFD receives a file descriptor from sock.
func receiveFD(sock int) (int, error) {
	// Allocate 4 bytes for receiving an fd.
	buf := make([]byte, unix.CmsgSpace(unix.SizeofInt))

	// Receive message, read out-of-band data containing fd, ignore payload.
	_, oobn, _, _, err := unix.Recvmsg(sock, []byte{0}, buf, unix.MSG_CMSG_CLOEXEC)
	if err != nil {
		return -1, fmt.Errorf("recvmsg: %w", err)
	}

	// Parse the control messages.
	msgs, err := unix.ParseSocketControlMessage(buf[:oobn])
	if err != nil {
		return -1, fmt.Errorf("parse socket control message: %w", err)
	}

	if len(msgs) != 1 {
		return -1, fmt.Errorf("expected 1 control message, got: %d", len(msgs))
	}

	// Extract fds from the control message.
	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil {
		return -1, fmt.Errorf("parse unix rights: %w", err)
	}

	if len(fds) != 1 {
		return -1, fmt.Errorf("expected 1 fd, got: %d", len(fds))
	}

	return fds[0], nil
}

// sendReady sends a message to the child over sock indicating that bpffs
// delegation is done.
func sendReady(sock int) error {
	if err := unix.Sendmsg(sock, []byte{readyMarker}, nil, nil, 0); err != nil {
		return fmt.Errorf("send ready marker: %w", err)
	}

	return nil
}

// waitReady waits for a message from the parent over sock indicating that the
// child can continue with the test.
func waitReady(sock int) error {
	var buf [1]byte
	n, _, _, _, err := unix.Recvmsg(sock, buf[:], nil, 0)
	if err != nil {
		return fmt.Errorf("receive message: %w", err)
	}

	if n != 1 {
		return fmt.Errorf("short read waiting for ready marker: %d", n)
	}

	if buf[0] != readyMarker {
		return fmt.Errorf("message did not contain %x", readyMarker)
	}

	return nil
}

// configureDelegated configures the bpffs file descriptor with the given
// delegated permissions.
func configureDelegated(bpffs int, delegated Delegated) error {
	if err := delegateFSConfig(bpffs, "delegate_cmds", delegated.Cmds); err != nil {
		return err
	}
	if err := delegateFSConfig(bpffs, "delegate_maps", delegated.Maps); err != nil {
		return err
	}
	if err := delegateFSConfig(bpffs, "delegate_progs", delegated.Progs); err != nil {
		return err
	}
	if err := delegateFSConfig(bpffs, "delegate_attachs", delegated.AttachTypes); err != nil {
		return err
	}
	if err := unix.FsconfigCreate(bpffs); err != nil {
		return fmt.Errorf("create fsconfig: %w", err)
	}
	return nil
}

func delegateFSConfig[T ~uint32](bpffs int, key string, delegates []T) error {
	d, err := delegateToHex(delegates)
	if err != nil {
		return fmt.Errorf("convert delegated permissions to hex: %w", err)
	}
	if err := unix.FsconfigSetString(bpffs, key, d); err != nil {
		return fmt.Errorf("set fsconfig %s: %w", key, err)
	}
	return nil
}

// delegateToHex takes a list of cmd/map/program/attach types and returns a hex
// string of the ORed bitmask of those types. Returns 'any' if the list contains
// math.MaxUint32, which is the value used by the kernel to indicate that all
// types of that kind are delegated.
func delegateToHex[T ~uint32](types []T) (string, error) {
	const delegateAny = math.MaxUint32

	var res uint64
	for _, v := range types {
		if uint32(v) == delegateAny {
			return "any", nil
		}
		if v >= 64 {
			return "", fmt.Errorf("delegate value out of range: %d", v)
		}
		res |= uint64(1) << v
	}

	return fmt.Sprintf("0x%x", res), nil
}

func panicf(format string, args ...any) {
	panic(fmt.Sprintf(format, args...))
}
