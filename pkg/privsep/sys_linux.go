package privsep

import (
	"fmt"
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// controlFile runs fn on the raw descriptor without switching f to blocking
// mode (unlike f.Fd()), so Close still interrupts pending reads.
func controlFile(f *os.File, fn func(fd int) error) error {
	raw, err := f.SyscallConn()
	if err != nil {
		return err
	}

	var inner error
	if err := raw.Control(func(fd uintptr) { inner = fn(int(fd)) }); err != nil {
		return err
	}

	return inner
}

// openPTY allocates a pseudo-terminal pair. pacman runs on the slave side so
// that prompts and progress bars behave as on a real terminal; the broker
// relays the master side over the socket.
func openPTY() (master, slave *os.File, err error) {
	master, err = os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}

	var n uint32

	err = controlFile(master, func(fd int) error {
		if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
			return err
		}

		var errG error
		n, errG = unix.IoctlGetUint32(fd, unix.TIOCGPTN)

		return errG
	})
	if err != nil {
		master.Close()
		return nil, nil, fmt.Errorf("privsep: pty setup: %w", err)
	}

	slave, err = os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		return nil, nil, err
	}

	return master, slave, nil
}

func setWinsize(f *os.File, rows, cols uint16) error {
	if rows == 0 || cols == 0 {
		return nil
	}

	return controlFile(f, func(fd int) error {
		return unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &unix.Winsize{Row: rows, Col: cols})
	})
}

// peerCred returns the kernel-verified credentials of the other end of a
// unix socket. For the connecting side these are the credentials of the
// process that called listen(); for the accepting side, those of the process
// that called connect(). They cannot be forged by an unprivileged process.
func peerCred(c *net.UnixConn) (*unix.Ucred, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}

	var (
		cred  *unix.Ucred
		inner error
	)

	if err := raw.Control(func(fd uintptr) {
		cred, inner = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return nil, err
	}

	return cred, inner
}
