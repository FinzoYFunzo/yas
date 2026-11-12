package privsep

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

const defaultAcceptTimeout = 30 * time.Second

// ExitError mirrors pacman's exit status as seen through the broker.
type ExitError struct {
	Code int
}

func (e *ExitError) Error() string { return fmt.Sprintf("exit status %d", e.Code) }

// ExitCode lets callers treat it like *exec.ExitError.
func (e *ExitError) ExitCode() int { return e.Code }

// StartOptions configures how the broker is launched.
type StartOptions struct {
	// Executable is the binary that implements the broker (os.Executable()).
	Executable string
	// PacmanBin and PacmanConf are fixed for the whole session.
	PacmanBin  string
	PacmanConf string
	// Elevate wraps argv with the privilege elevator (sudo, doas, run0...).
	Elevate func(argv []string) *exec.Cmd
	// ClearCredentials runs after the broker connected, e.g. `sudo -k`, so
	// no reusable credential stays cached on the terminal.
	ClearCredentials func()
	AcceptTimeout    time.Duration
	// allowUnprivilegedPeer is only set by tests.
	allowUnprivilegedPeer bool
}

// Client is yay's handle to a running broker.
type Client struct {
	conn      *net.UnixConn
	wmu       sync.Mutex
	BrokerPID int

	// Stdin and Stdout are the user's terminal; replaceable in tests.
	Stdin  *os.File
	Stdout io.Writer
}

// listener is the private rendezvous point: a socket in a fresh 0700
// directory, removed as soon as the broker connected.
type listener struct {
	ln   *net.UnixListener
	dir  string
	path string
}

func listenPrivate() (*listener, error) {
	dir, err := os.MkdirTemp("", "yas-privsep-")
	if err != nil {
		return nil, err
	}

	path := filepath.Join(dir, "broker.sock")

	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}

	return &listener{ln: ln, dir: dir, path: path}, nil
}

func (l *listener) Close() {
	l.ln.Close()
	os.RemoveAll(l.dir)
}

// accept waits for the broker. A peer that is not root is rejected and we
// keep waiting, so another process of the same user cannot pose as the
// broker and receive yay's requests.
func (l *listener) accept(timeout time.Duration, allowUnprivileged bool) (*Client, error) {
	deadline := time.Now().Add(timeout)

	for {
		if err := l.ln.SetDeadline(deadline); err != nil {
			return nil, err
		}

		conn, err := l.ln.AcceptUnix()
		if err != nil {
			return nil, fmt.Errorf("waiting for privileged broker: %w", err)
		}

		cred, err := peerCred(conn)
		if err != nil || (cred.Uid != 0 && !(allowUnprivileged && int(cred.Uid) == os.Getuid())) {
			conn.Close()
			continue
		}

		_ = conn.SetReadDeadline(deadline)

		typ, payload, err := readFrame(conn)
		if err != nil || typ != frameHello {
			conn.Close()
			continue
		}

		var hello Hello
		if err := json.Unmarshal(payload, &hello); err != nil || hello.Version != ProtocolVersion {
			conn.Close()
			return nil, fmt.Errorf("broker protocol mismatch (got %d, want %d)", hello.Version, ProtocolVersion)
		}

		_ = conn.SetReadDeadline(time.Time{})

		return &Client{conn: conn, BrokerPID: hello.PID, Stdin: os.Stdin, Stdout: os.Stdout}, nil
	}
}

// Start launches the broker through the privilege elevator (the only
// password prompt of the session) and waits for it to connect back.
func Start(opts StartOptions) (*Client, error) {
	if opts.AcceptTimeout == 0 {
		opts.AcceptTimeout = defaultAcceptTimeout
	}

	conf, err := filepath.Abs(opts.PacmanConf)
	if err != nil {
		return nil, err
	}

	l, err := listenPrivate()
	if err != nil {
		return nil, err
	}
	defer l.Close()

	argv := []string{
		opts.Executable, BrokerArg,
		"--socket", l.path,
		"--client-pid", strconv.Itoa(os.Getpid()),
		"--client-uid", strconv.Itoa(os.Getuid()),
		"--pacman", opts.PacmanBin,
		"--pacman-conf", conf,
	}

	cmd := opts.Elevate(argv)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("launching privileged broker: %w", err)
	}

	c, err := l.accept(opts.AcceptTimeout, opts.allowUnprivilegedPeer || insecureTestMode)
	if err != nil {
		return nil, err
	}

	if opts.ClearCredentials != nil {
		opts.ClearCredentials()
	}

	return c, nil
}

// Close ends the session; the broker exits on EOF.
func (c *Client) Close() error {
	return c.conn.Close()
}

func (c *Client) send(typ byte, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	return writeFrame(c.conn, typ, payload)
}

func (c *Client) sendJSON(typ byte, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return err
	}

	return c.send(typ, payload)
}

func (c *Client) winsize() (rows, cols uint16) {
	for _, f := range []*os.File{os.Stdout, c.Stdin} {
		if f == nil {
			continue
		}

		if w, h, err := term.GetSize(int(f.Fd())); err == nil {
			return uint16(h), uint16(w)
		}
	}

	return 0, 0
}

// Run executes one pacman request through the broker, relaying the user's
// terminal to pacman's pty until it exits.
func (c *Client) Run(req Request) error {
	req.Term = os.Getenv("TERM")
	req.Rows, req.Cols = c.winsize()

	if err := c.sendJSON(frameRequest, req); err != nil {
		return fmt.Errorf("privileged broker: %w", err)
	}

	stdinFd := int(c.Stdin.Fd())
	if term.IsTerminal(stdinFd) {
		// Raw mode: keystrokes (including ^C) go to pacman's pty untouched,
		// and the pty does the echoing and line editing.
		if state, err := term.MakeRaw(stdinFd); err == nil {
			defer func() { _ = term.Restore(stdinFd, state) }()
		}
	}

	done := make(chan struct{})

	var wg sync.WaitGroup

	wg.Add(2)

	go func() { defer wg.Done(); c.pumpStdin(stdinFd, done) }()
	go func() { defer wg.Done(); c.forwardWinch(done) }()

	// Stop the helpers before returning so they never steal input meant for
	// yay's own prompts.
	defer func() { close(done); wg.Wait() }()

	for {
		typ, payload, err := readFrame(c.conn)
		if err != nil {
			return fmt.Errorf("lost connection to privileged broker: %w", err)
		}

		switch typ {
		case frameOutput:
			_, _ = c.Stdout.Write(payload)
		case frameExit:
			var st ExitStatus
			if err := json.Unmarshal(payload, &st); err != nil {
				return err
			}

			if st.Error != "" {
				return fmt.Errorf("privileged broker: %s", st.Error)
			}

			if st.Code != 0 {
				return &ExitError{Code: st.Code}
			}

			return nil
		}
	}
}

func (c *Client) pumpStdin(fd int, done <-chan struct{}) {
	buf := make([]byte, 4096)
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}

	for {
		select {
		case <-done:
			return
		default:
		}

		n, err := unix.Poll(fds, 50)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}

			return
		}

		if n == 0 {
			continue
		}

		if fds[0].Revents&unix.POLLIN == 0 {
			return // hangup or error on stdin
		}

		r, err := unix.Read(fd, buf)
		if r <= 0 || err != nil {
			return
		}

		if c.send(frameStdin, buf[:r]) != nil {
			return
		}
	}
}

func (c *Client) forwardWinch(done <-chan struct{}) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	defer signal.Stop(ch)

	for {
		select {
		case <-done:
			return
		case <-ch:
			rows, cols := c.winsize()
			_ = c.sendJSON(frameWinsize, Winsize{Rows: rows, Cols: cols})
		}
	}
}
