package exe

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Jguer/yay/v13/pkg/privsep"
	"github.com/Jguer/yay/v13/pkg/settings/parser"
	"github.com/Jguer/yay/v13/pkg/text"
)

// fakeSudo logs every invocation and fails "sudo -v" (as a timed-out or
// wrong password would). With -n it fails too unless SUDO_N_OK is set.
const fakeSudo = `#!/bin/sh
echo "$*" >> "$FAKE_SUDO_LOG"
if [ "$1" = "-n" ]; then
  [ -n "$SUDO_N_OK" ] && exit 0
  exit 1
fi
[ -n "$SUDO_V_OK" ] && exit 0
echo "sudo: timed out reading password" >&2
exit 1
`

func newSudoLoopBuilder(t *testing.T) (*CmdBuilder, string) {
	t.Helper()

	dir := t.TempDir()
	bin := filepath.Join(dir, "sudo")
	logFile := filepath.Join(dir, "calls.log")
	require.NoError(t, os.WriteFile(bin, []byte(fakeSudo), 0o755))
	t.Setenv("FAKE_SUDO_LOG", logFile)

	logger := text.NewLogger(io.Discard, io.Discard, strings.NewReader(""), false, "test")

	return &CmdBuilder{SudoBin: bin, Runner: NewOSRunner(logger), Log: logger}, logFile
}

func calls(t *testing.T, logFile string) []string {
	t.Helper()

	data, err := os.ReadFile(logFile)
	if os.IsNotExist(err) {
		return nil
	}

	require.NoError(t, err)

	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

// The original implementation retried `sudo -v` forever (632 calls in 2s in
// our PoC); every failure is a pam_faillock strike. Now: exactly one attempt.
func TestSudoLoopFailsSafe(t *testing.T) {
	b, logFile := newSudoLoopBuilder(t)

	done := make(chan error, 1)
	go func() { done <- b.SudoLoop() }()

	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("SudoLoop keeps retrying after a failed authentication")
	}

	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, []string{"-v"}, calls(t, logFile), "a single sudo invocation, no retries")
}

// With timestamp_timeout=0 sudo caches nothing: the loop is disabled instead
// of prompting every 241 seconds.
func TestSudoLoopDisabledWithoutCredentialCache(t *testing.T) {
	b, logFile := newSudoLoopBuilder(t)
	t.Setenv("SUDO_V_OK", "1")

	require.NoError(t, b.SudoLoop())

	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, []string{"-v", "-n -v"}, calls(t, logFile))
}

func TestBrokerRequestFromArguments(t *testing.T) {
	t.Parallel()

	args := parser.MakeArguments()
	args.Op = "U"
	require.NoError(t, args.AddArg("asdeps"))
	args.AddTarget("foo-1.0-1-x86_64.pkg.tar.zst")
	args.AddTarget("/var/cache/pacman/pkg/bar-1-1-any.pkg.tar.zst")

	req := brokerRequest(args, true)

	cwd, err := os.Getwd()
	require.NoError(t, err)

	assert.Equal(t, "U", req.Op)
	assert.ElementsMatch(t, []privsep.Flag{{Name: "asdeps"}, {Name: "noconfirm"}}, req.Flags)
	assert.Equal(t, []string{
		filepath.Join(cwd, "foo-1.0-1-x86_64.pkg.tar.zst"),
		"/var/cache/pacman/pkg/bar-1-1-any.pkg.tar.zst",
	}, req.Targets, "relative package paths are made absolute")
}

func TestPrivSepDisabledKeepsClassicPath(t *testing.T) {
	t.Parallel()

	logger := text.NewLogger(io.Discard, io.Discard, strings.NewReader(""), false, "test")
	b := &CmdBuilder{SudoBin: "sudo", PacmanBin: "pacman", PacmanConfigPath: "/etc/pacman.conf", Log: logger}

	args := parser.MakeArguments()
	args.Op = "S"
	args.AddTarget("htop")

	cmd := b.BuildPacmanCmd(t.Context(), args, parser.ModeAny, false)
	_, routed := b.takeBrokerRequest(cmd)
	assert.False(t, routed)
}
