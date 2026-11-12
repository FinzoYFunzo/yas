package privsep

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/syslog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

// BrokerArg is the hidden first argument that turns the yay binary into the
// privileged broker. It is handled in main() before any configuration is read.
const BrokerArg = "--yas-privsep-broker"

const dialTimeout = 10 * time.Second

type brokerConfig struct {
	socket     string
	clientPID  int
	clientUID  int
	pacman     string
	pacmanConf string
	daemon     bool
}

// IsBrokerInvocation reports whether args (os.Args) ask for the broker.
func IsBrokerInvocation(args []string) bool {
	return len(args) > 1 && args[1] == BrokerArg
}

func parseBrokerArgs(args []string) (*brokerConfig, error) {
	fs := flag.NewFlagSet("yas-broker", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	cfg := &brokerConfig{}
	fs.StringVar(&cfg.socket, "socket", "", "")
	fs.IntVar(&cfg.clientPID, "client-pid", 0, "")
	fs.IntVar(&cfg.clientUID, "client-uid", -1, "")
	fs.StringVar(&cfg.pacman, "pacman", "pacman", "")
	fs.StringVar(&cfg.pacmanConf, "pacman-conf", "/etc/pacman.conf", "")
	fs.BoolVar(&cfg.daemon, "daemon", false, "")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	switch {
	case fs.NArg() != 0:
		return nil, fmt.Errorf("unexpected arguments: %v", fs.Args())
	case !filepath.IsAbs(cfg.socket):
		return nil, errors.New("--socket must be an absolute path")
	case cfg.clientPID <= 1:
		return nil, errors.New("--client-pid is required")
	case cfg.clientUID < 0:
		return nil, errors.New("--client-uid is required")
	case !filepath.IsAbs(cfg.pacmanConf):
		return nil, errors.New("--pacman-conf must be an absolute path")
	}

	// Resolved with the broker's own PATH (sudo's secure_path), never the
	// caller's.
	bin, err := exec.LookPath(cfg.pacman)
	if err != nil {
		return nil, fmt.Errorf("pacman binary: %w", err)
	}

	if cfg.pacman, err = filepath.Abs(bin); err != nil {
		return nil, err
	}

	return cfg, nil
}

// BrokerMain is the entry point of the privileged broker. It is run twice:
// first by sudo (launcher), which validates the arguments and re-executes
// itself detached from sudo's session, then as the detached daemon that
// serves requests. Detaching lets sudo exit right away, so sudo never keeps
// relaying (and stealing) terminal input during the yay session.
func BrokerMain(args []string) int {
	rest := args[2:]

	cfg, err := parseBrokerArgs(rest)
	if err != nil {
		fmt.Fprintln(os.Stderr, "yas-broker:", err)
		return 2
	}

	if os.Geteuid() != 0 && !insecureTestMode {
		fmt.Fprintln(os.Stderr, "yas-broker: must be started as root (through sudo)")
		return 1
	}

	if !cfg.daemon {
		if err := launchDaemon(rest); err != nil {
			fmt.Fprintln(os.Stderr, "yas-broker:", err)
			return 1
		}

		return 0
	}

	audit := newAuditLogger()
	if err := runDaemon(cfg, audit); err != nil {
		audit.Printf("error: %v", err)
		return 1
	}

	return 0
}

func launchDaemon(rest []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer devnull.Close()

	cmd := exec.Command(exe, append([]string{BrokerArg, "--daemon"}, rest...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, devnull, devnull
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		return err
	}

	return cmd.Process.Release()
}

func newAuditLogger() *log.Logger {
	if w, err := syslog.New(syslog.LOG_AUTHPRIV|syslog.LOG_NOTICE, "yas-broker"); err == nil {
		return log.New(w, "", 0)
	}

	return log.New(io.Discard, "", 0)
}

func runDaemon(cfg *brokerConfig, audit *log.Logger) error {
	conn, err := net.DialTimeout("unix", cfg.socket, dialTimeout)
	if err != nil {
		return fmt.Errorf("connect %s: %w", cfg.socket, err)
	}
	defer conn.Close()

	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("not a unix socket")
	}

	// The listening side must be exactly the yay process that launched us.
	// Another process of the same user cannot fake its pid in SO_PEERCRED.
	cred, err := peerCred(uc)
	if err != nil {
		return fmt.Errorf("SO_PEERCRED: %w", err)
	}

	if int(cred.Pid) != cfg.clientPID || int(cred.Uid) != cfg.clientUID {
		return fmt.Errorf("peer mismatch: got pid=%d uid=%d, expected pid=%d uid=%d",
			cred.Pid, cred.Uid, cfg.clientPID, cfg.clientUID)
	}

	b := &broker{conn: uc, pacman: cfg.pacman, pacmanConf: cfg.pacmanConf, audit: audit}
	if err := b.sendJSON(frameHello, Hello{Version: ProtocolVersion, PID: os.Getpid()}); err != nil {
		return err
	}

	audit.Printf("session start: client pid=%d uid=%d, pacman=%s config=%s",
		cfg.clientPID, cfg.clientUID, cfg.pacman, cfg.pacmanConf)
	b.serve()
	audit.Printf("session end: client pid=%d", cfg.clientPID)

	return nil
}

type frame struct {
	typ     byte
	payload []byte
}

type broker struct {
	conn       net.Conn
	wmu        sync.Mutex
	pacman     string
	pacmanConf string
	audit      *log.Logger
}

func (b *broker) send(typ byte, payload []byte) error {
	b.wmu.Lock()
	defer b.wmu.Unlock()

	return writeFrame(b.conn, typ, payload)
}

func (b *broker) sendJSON(typ byte, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return err
	}

	return b.send(typ, payload)
}

// serve handles requests one at a time until the client closes the socket.
func (b *broker) serve() {
	frames := make(chan frame)

	go func() {
		defer close(frames)

		for {
			typ, payload, err := readFrame(b.conn)
			if err != nil {
				return
			}

			frames <- frame{typ, payload}
		}
	}()

	for f := range frames {
		if f.typ != frameRequest {
			continue // stray input between requests is discarded
		}

		var req Request
		if err := json.Unmarshal(f.payload, &req); err != nil {
			_ = b.sendJSON(frameExit, ExitStatus{Code: 1, Error: "malformed request"})
			continue
		}

		if closed := b.handle(&req, frames); closed {
			return
		}
	}
}

func (b *broker) handle(req *Request, frames <-chan frame) (closed bool) {
	argv, err := BuildArgv(b.pacman, b.pacmanConf, req)
	if err != nil {
		b.audit.Printf("DENIED op=%q flags=%v targets=%q: %v", req.Op, req.Flags, req.Targets, err)
		_ = b.sendJSON(frameExit, ExitStatus{Code: 1, Error: err.Error()})

		return false
	}

	b.audit.Printf("EXEC %s", strings.Join(argv, " "))

	code, runErr, closed := b.runPTY(argv, req, frames)

	status := ExitStatus{Code: code}
	if runErr != nil {
		status.Error = runErr.Error()
		if status.Code == 0 {
			status.Code = 1
		}
	}

	b.audit.Printf("EXIT %d", status.Code)

	if !closed {
		_ = b.sendJSON(frameExit, status)
	}

	return closed
}

var termRe = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}$`)

// pacmanEnv starts from the broker's environment (already sanitized by sudo)
// and drops loader variables as defense in depth.
func pacmanEnv(term string) []string {
	env := make([]string, 0, len(os.Environ())+1)

	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "LD_") || name == "TERM" {
			continue
		}

		env = append(env, kv)
	}

	if termRe.MatchString(term) {
		env = append(env, "TERM="+term)
	}

	return env
}

func (b *broker) runPTY(argv []string, req *Request, frames <-chan frame) (code int, err error, closed bool) {
	master, slave, err := openPTY()
	if err != nil {
		return 1, err, false
	}
	defer master.Close()

	_ = setWinsize(master, req.Rows, req.Cols)

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.Dir = "/"
	cmd.Env = pacmanEnv(req.Term)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}

	err = cmd.Start()
	slave.Close()

	if err != nil {
		return 1, err, false
	}

	outDone := make(chan struct{})

	go func() {
		defer close(outDone)

		buf := make([]byte, 32*1024)

		for {
			n, err := master.Read(buf)
			if n > 0 {
				_ = b.send(frameOutput, buf[:n])
			}

			if err != nil {
				return // EIO once pacman and its children closed the slave
			}
		}
	}()

	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()

	for {
		select {
		case f, ok := <-frames:
			if !ok {
				// yay went away: let pacman finish its transaction, then exit.
				frames, closed = nil, true
				continue
			}

			switch f.typ {
			case frameStdin:
				_, _ = master.Write(f.payload)
			case frameWinsize:
				var ws Winsize
				if json.Unmarshal(f.payload, &ws) == nil {
					_ = setWinsize(master, ws.Rows, ws.Cols)
				}
			}
		case werr := <-waitCh:
			select {
			case <-outDone:
			case <-time.After(2 * time.Second):
			}

			code, err := exitCode(werr)

			return code, err, closed
		}
	}
}

func exitCode(werr error) (int, error) {
	if werr == nil {
		return 0, nil
	}

	var ee *exec.ExitError
	if !errors.As(werr, &ee) {
		return 1, werr
	}

	if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal()), nil
	}

	return ee.ExitCode(), nil
}
