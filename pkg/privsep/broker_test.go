package privsep

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFrameRoundTrip(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	require.NoError(t, writeJSON(&buf, frameRequest, Request{Op: "S", Targets: []string{"htop"}}))
	require.NoError(t, writeFrame(&buf, frameStdin, []byte("y\n")))

	typ, payload, err := readFrame(&buf)
	require.NoError(t, err)
	assert.Equal(t, frameRequest, typ)

	var req Request
	require.NoError(t, json.Unmarshal(payload, &req))
	assert.Equal(t, []string{"htop"}, req.Targets)

	typ, payload, err = readFrame(&buf)
	require.NoError(t, err)
	assert.Equal(t, frameStdin, typ)
	assert.Equal(t, "y\n", string(payload))

	assert.ErrorIs(t, writeFrame(io.Discard, frameOutput, make([]byte, maxFrame+1)), errFrameTooLarge)
}

func TestReadFrameRejectsOversizedHeader(t *testing.T) {
	t.Parallel()

	_, _, err := readFrame(bytes.NewReader([]byte{frameRequest, 0xff, 0xff, 0xff, 0xff}))
	assert.ErrorIs(t, err, errFrameTooLarge)
}

// fakePacman behaves like an interactive pacman: prints its argv, reports
// whether it got a terminal, asks for confirmation and exits with code 3.
const fakePacman = `#!/bin/sh
echo "ARGS: $*"
if [ -t 0 ]; then echo "TTY=yes"; fi
printf "Proceed? [Y/n] "
read ans
echo "ANSWER=$ans"
exit 3
`

type fixture struct {
	pacman string
	conf   string
	pkg    string
}

func newFixture(t *testing.T) fixture {
	t.Helper()

	dir := t.TempDir()
	f := fixture{
		pacman: filepath.Join(dir, "pacman"),
		conf:   filepath.Join(dir, "pacman.conf"),
		pkg:    filepath.Join(dir, "foo-1.0-1-x86_64.pkg.tar.zst"),
	}

	require.NoError(t, os.WriteFile(f.pacman, []byte(fakePacman), 0o755))
	require.NoError(t, os.WriteFile(f.conf, []byte("[options]\n"), 0o644))
	require.NoError(t, os.WriteFile(f.pkg, []byte("pkg"), 0o644))

	return f
}

func quietLog() *log.Logger { return log.New(io.Discard, "", 0) }

// TestBrokerEndToEnd runs the real broker daemon and client over a real unix
// socket and pty, with a fake pacman.
func TestBrokerEndToEnd(t *testing.T) {
	fx := newFixture(t)

	l, err := listenPrivate()
	require.NoError(t, err)
	defer l.Close()

	cfg := &brokerConfig{
		socket: l.path, clientPID: os.Getpid(), clientUID: os.Getuid(),
		pacman: fx.pacman, pacmanConf: fx.conf,
	}

	daemonErr := make(chan error, 1)
	go func() { daemonErr <- runDaemon(cfg, quietLog()) }()

	c, err := l.accept(5*time.Second, true)
	require.NoError(t, err)

	inR, inW, err := os.Pipe()
	require.NoError(t, err)
	defer inR.Close()

	var out bytes.Buffer
	c.Stdin, c.Stdout = inR, &out

	_, err = inW.WriteString("y\n")
	require.NoError(t, err)

	err = c.Run(Request{Op: "U", Flags: []Flag{{Name: "noconfirm"}}, Targets: []string{fx.pkg}})

	var ee *ExitError
	require.ErrorAs(t, err, &ee, "output: %s", out.String())
	assert.Equal(t, 3, ee.ExitCode(), "pacman's exit code is propagated")

	got := out.String()
	assert.Contains(t, got, "ARGS: --config "+fx.conf+" -U --noconfirm -- "+fx.pkg)
	assert.Contains(t, got, "TTY=yes", "pacman runs on a pty")
	assert.Contains(t, got, "ANSWER=y", "user input reaches pacman")

	// A forbidden option is refused without running anything.
	out.Reset()
	err = c.Run(Request{Op: "U", Flags: []Flag{{Name: "hookdir", Value: "/tmp/hooks"}}, Targets: []string{fx.pkg}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
	assert.NotContains(t, out.String(), "ARGS:")

	// The broker exits when yay closes the session.
	inW.Close()
	require.NoError(t, c.Close())

	select {
	case err := <-daemonErr:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("broker did not exit after the client closed the socket")
	}
}

// TestBrokerRejectsImpostorListener: the broker only talks to the exact yay
// process (pid) that launched it.
func TestBrokerRejectsImpostorListener(t *testing.T) {
	fx := newFixture(t)

	l, err := listenPrivate()
	require.NoError(t, err)
	defer l.Close()

	cfg := &brokerConfig{
		socket: l.path, clientPID: os.Getpid() + 100000, clientUID: os.Getuid(),
		pacman: fx.pacman, pacmanConf: fx.conf,
	}

	daemonErr := make(chan error, 1)
	go func() { daemonErr <- runDaemon(cfg, quietLog()) }()

	_, err = l.accept(time.Second, true)
	require.Error(t, err, "no session must be established")

	err = <-daemonErr
	require.Error(t, err)
	assert.Contains(t, err.Error(), "peer mismatch")
}

// TestClientRejectsUnprivilegedBroker: a process of the same user that
// connects to yay's socket is not accepted as the broker.
func TestClientRejectsUnprivilegedBroker(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("needs an unprivileged user")
	}

	fx := newFixture(t)

	l, err := listenPrivate()
	require.NoError(t, err)
	defer l.Close()

	cfg := &brokerConfig{
		socket: l.path, clientPID: os.Getpid(), clientUID: os.Getuid(),
		pacman: fx.pacman, pacmanConf: fx.conf,
	}

	go func() { _ = runDaemon(cfg, quietLog()) }()

	_, err = l.accept(time.Second, false)
	require.Error(t, err)
	assert.True(t, errors.Is(err, os.ErrDeadlineExceeded) || strings.Contains(err.Error(), "timeout"), err)
}

func TestParseBrokerArgs(t *testing.T) {
	t.Parallel()

	conf := filepath.Join(t.TempDir(), "pacman.conf")

	_, err := parseBrokerArgs([]string{"--socket", "relative.sock", "--client-pid", "100", "--client-uid", "1000", "--pacman", "sh", "--pacman-conf", conf})
	require.Error(t, err)

	_, err = parseBrokerArgs([]string{"--socket", "/tmp/x.sock", "--client-pid", "100", "--client-uid", "1000", "--pacman", "sh", "--pacman-conf", conf, "extra"})
	require.Error(t, err)

	cfg, err := parseBrokerArgs([]string{"--socket", "/tmp/x.sock", "--client-pid", "100", "--client-uid", "1000", "--pacman", "sh", "--pacman-conf", conf})
	require.NoError(t, err)
	assert.True(t, filepath.IsAbs(cfg.pacman), "pacman is resolved to an absolute path")
}
