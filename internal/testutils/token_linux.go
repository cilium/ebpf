//go:build unix

package testutils

import (
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/cilium/ebpf/internal/platform"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/unix"
)

func init() {
	if stage, ok := os.LookupEnv(TOKEN_SUBTEST); ok {
		// If this is stage 2 of the subtest, we let the tests run.
		if stage != "1" {
			return
		}

		// If this is stage 1 of the subtest, we setup the environment and then re-exec ourselves.
		setupSubtest()
	}
}

// RunWithToken sets up an environment with a BPFFS with the provided delegated permissions.
//
// When called, the calling test method is re-executed in a subprocess with the environment set up. RunWithToken
// returns true in the parent process, and false in the child process, so that the test can distinguish between them and
// only run the actual test logic in the child process.
func RunWithToken(tb testing.TB, delegated Delegated) bool {
	tb.Helper()

	if !platform.IsLinux {
		tb.Skip("Tokens only work on linux")
	}

	SkipOnOldKernel(tb, "6.9", "BPF_TOKEN_CREATE")

	// Detect when we are running the the child process and bail out.
	if _, ok := os.LookupEnv(TOKEN_SUBTEST); ok {
		return false
	}

	// Run just the current test in a subprocess
	args := []string{
		"-test.run=^" + tb.Name() + "$",
	}

	// If we are running in verbose mode, pass the flag to the subtest as well.
	if testing.Verbose() {
		args = append(args, "-test.v")
	}

	// Call the current test binary (os.Args[0])
	cmd := exec.CommandContext(tb.Context(), os.Args[0], args...)

	// Pass an environment variable to the subtest to indicate that it should run, and not skip.
	cmd.Env = append(cmd.Environ(), TOKEN_SUBTEST+"=1")

	// Inherit the test's standard output and error so that we can see the subtest's logs and errors in real time.
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout

	// Create a socket pair for communication between the parent and child process.
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		tb.Fatal(err)
	}
	parent, child := pair[0], pair[1]
	defer unix.Close(parent)

	// Files can only be read if the owning user and group are mapped into the user namespace.
	// So find out all UIDs and GIDs of users on the system and map them into the user namespace of the child process.
	uidMappings, gidMappings, err := parseUIDsGIDs()
	if err != nil {
		tb.Fatal(err)
	}

	// Let the child process inherit the child's end of the socket pair.
	cmd.ExtraFiles = []*os.File{os.NewFile(uintptr(child), "child-socket")}

	cmd.SysProcAttr = &unix.SysProcAttr{
		// Run the child process in a new user namespace and mount namespace.
		Cloneflags: unix.CLONE_NEWUSER | unix.CLONE_NEWNS,
		// Give CAP_SYS_ADMIN for the initial mount setup,
		// CAP_DAC_READ_SEARCH to allow reading files regardless of permissions,
		// and CAP_BPF so it can do BPF ops with tokens.
		AmbientCaps: []uintptr{unix.CAP_SYS_ADMIN, unix.CAP_DAC_READ_SEARCH, unix.CAP_BPF},
		UidMappings: uidMappings,
		GidMappings: gidMappings,
	}

	// Start the child process in the background.
	err = cmd.Start()
	if err != nil {
		unix.Close(child)
		tb.Fatal(err)
	}
	unix.Close(child)

	// Receive the bpffs context fd from the child process.
	fds, err := recvFDs(1, parent)
	if err != nil {
		tb.Fatal(err)
	}
	bpffs := fds[0]

	err = configureDelegated(bpffs, delegated)
	if err != nil {
		tb.Fatal(err)
	}

	// Send back a message, we don't care about the content, just a signal to tell the child process that the bpffs is
	// configured and it can proceed with the test.
	err = unix.Sendmsg(parent, []byte("done"), nil, nil, 0)
	if err != nil {
		tb.Fatal(err)
	}

	err = cmd.Wait()
	if err != nil {
		tb.Fatal(err)
	}

	return true
}

func parseUIDsGIDs() (uids, gids []syscall.SysProcIDMap, err error) {
	// Files can only be read if the owning user and group are mapped into the user namespace.
	// So find out all uids and gids of users on the system and map them into the user namespace of the child process.
	passwdFile, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil, nil, fmt.Errorf("read /etc/passwd: %v", err)
	}

	for line := range strings.Lines(string(passwdFile)) {
		cols := strings.Split(line, ":")
		uid, err := strconv.Atoi(cols[2])
		if err != nil {
			return nil, nil, fmt.Errorf("parse uid: %v", err)
		}
		// Users with UID < 1000 are typically system users, we don't expect to need to read files
		// owned by them in tests.
		if uid < 1000 {
			continue
		}
		uids = append(uids, syscall.SysProcIDMap{
			ContainerID: uid,
			HostID:      uid,
			Size:        1,
		})

		gid, err := strconv.Atoi(cols[3])
		if err != nil {
			return nil, nil, fmt.Errorf("parse gid: %v", err)
		}
		gids = append(gids, syscall.SysProcIDMap{
			ContainerID: gid,
			HostID:      gid,
			Size:        1,
		})
	}

	return uids, gids, nil
}

// setupSubtest does the child side setup needed to create a BPFFS with delegated permissions.
// Once the setup is done, we drop CAP_SYS_ADMIN, re-exec the binary, So this function never returns control flow.
// The re-exec is needed to ensure that the test runs in a clean environment with only the capabilities we want, and to
// make it indistinguishable from a scenario where the BPFFS was set up by an external process before the test started.
func setupSubtest() {
	// Create a new bpffsCtx file system context
	bpffsCtxFd, err := unix.Fsopen("bpf", 0)
	if err != nil {
		panic(err)
	}

	bpffsCtx, err := sys.NewFD(bpffsCtxFd)
	if err != nil {
		panic(err)
	}
	defer bpffsCtx.Close()

	// Fd 0, 1, and 2 are taken by stdin, stdout, and stderr.
	// So files passed by `cmd.ExtraFiles` start at fd 3, which is our child socket.
	const childSocketFd = 3
	childSocket, err := sys.NewFD(childSocketFd)
	if err != nil {
		panic(err)
	}
	defer childSocket.Close()

	// Send the bpffs fd to the parent process so it can configure delegation on it and mount it.
	rights := unix.UnixRights(bpffsCtx.Int())
	err = unix.Sendmsg(childSocket.Int(), nil, rights, nil, 0)
	if err != nil {
		panic(err)
	}

	// Wait for the parent to send a message back, we don't care about the content,
	// we just want to make sure the parent has finished configuring delegation before we proceed.
	var buf [16]byte
	_, _, _, _, err = unix.Recvmsg(childSocket.Int(), buf[:], nil, 0)
	if err != nil {
		panic(err)
	}

	// Turn the filesystem context into a mount object. It is still detached at this point.
	bpffsMnt, err := unix.Fsmount(bpffsCtx.Int(), 0, 0)
	if err != nil {
		panic(err)
	}

	// Move the detached mount to /sys/fs/bpf, the default location.
	err = unix.MoveMount(bpffsMnt, "", unix.AT_FDCWD, "/sys/fs/bpf", unix.MOVE_MOUNT_F_EMPTY_PATH)
	if err != nil {
		panic(err)
	}

	// Drop all capabilities except for CAP_BPF and CAP_DAC_READ_SEARCH.
	// CAP_BPF is needed to do BPF syscalls with a token, and CAP_DAC_READ_SEARCH is needed to read source files which
	// will be owned by the user running the test, and we will be running as `nobody` in the user namespace.
	const caps = (uint64(1) << unix.CAP_BPF) | (uint64(1) << unix.CAP_DAC_READ_SEARCH)
	err = unix.Capset(unix.CapUserData{
		Effective:   caps,
		Permitted:   caps,
		Inheritable: caps,
	})
	if err != nil {
		panic(fmt.Sprintf("capset: %v", err))
	}

	// Mark next exec as stage 2, to actually execute the tests.
	env := os.Environ()
	i := slices.IndexFunc(env, func(s string) bool { return strings.HasPrefix(s, TOKEN_SUBTEST+"=") })
	env = slices.Replace(env, i, i+1, TOKEN_SUBTEST+"=2")

	// Re-exec ourselves so that its truly as if all of the setup was done before the test started.
	err = syscall.Exec(os.Args[0], os.Args, env)
	if err != nil {
		panic(fmt.Sprintf("exec: %v", err))
	}
}

// recvFDs receives file descriptors from the provided socket. It expects to receive `fdRecvCnt“ fds.
func recvFDs(fdRecvCnt int, sock int) ([]int, error) {
	// Allocate 4 bytes for every fd we expect to receive.
	buf := make([]byte, unix.CmsgSpace(fdRecvCnt*4))
	// Receive message, we only care about the out-of-band data containing the fds.
	_, _, _, _, err := unix.Recvmsg(sock, nil, buf, 0)
	if err != nil {
		return nil, fmt.Errorf("recvmsg: %w", err)
	}

	// Parse the control messages.
	msgs, err := unix.ParseSocketControlMessage(buf)
	if err != nil {
		return nil, fmt.Errorf("parse socket control message: %w", err)
	}

	var allfds []int
	for i := range msgs {
		// Extract the fds from the control message.
		msgfds, err := unix.ParseUnixRights(&msgs[i])
		if err != nil {
			return nil, fmt.Errorf("parse unix rights: %w", err)
		}
		allfds = append(allfds, msgfds...)
	}

	return allfds, nil
}

func configureDelegated(bpffs int, delegated Delegated) error {
	err := unix.FsconfigSetString(bpffs, "delegate_cmds", delegateString(delegated.Cmds))
	if err != nil {
		return fmt.Errorf("delegate_cmds: %w", err)
	}

	err = unix.FsconfigSetString(bpffs, "delegate_maps", delegateString(delegated.Maps))
	if err != nil {
		return fmt.Errorf("delegate_maps: %w", err)
	}

	err = unix.FsconfigSetString(bpffs, "delegate_progs", delegateString(delegated.Progs))
	if err != nil {
		return fmt.Errorf("delegate_progs: %w", err)
	}

	err = unix.FsconfigSetString(bpffs, "delegate_attachs", delegateString(delegated.AttachTypes))
	if err != nil {
		return fmt.Errorf("delegate_attachs: %w", err)
	}

	err = unix.FsconfigCreate(bpffs)
	if err != nil {
		return fmt.Errorf("fsconfig_create: %w", err)
	}

	return nil
}
