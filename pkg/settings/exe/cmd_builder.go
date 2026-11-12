package exe

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/leonelquinteros/gotext"

	"github.com/Jguer/yay/v13/pkg/privsep"
	"github.com/Jguer/yay/v13/pkg/settings"
	"github.com/Jguer/yay/v13/pkg/settings/parser"
	"github.com/Jguer/yay/v13/pkg/text"
)

const SudoLoopDuration = 241

var gitDenyList = mapset.NewThreadUnsafeSet(
	"GIT_WORK_TREE",
	"GIT_DIR",
)

type GitCmdBuilder interface {
	Runner
	BuildGitCmd(ctx context.Context, dir string, extraArgs ...string) *exec.Cmd
}

type ICmdBuilder interface {
	Runner
	BuildGitCmd(ctx context.Context, dir string, extraArgs ...string) *exec.Cmd
	BuildGPGCmd(ctx context.Context, extraArgs ...string) *exec.Cmd
	BuildMakepkgCmd(ctx context.Context, dir string, extraArgs ...string) *exec.Cmd
	BuildPacmanCmd(ctx context.Context, args *parser.Arguments, mode parser.TargetMode, noConfirm bool) *exec.Cmd
	AddMakepkgFlag(string)
	GetKeepSrc() bool
	SudoLoop() error
	StartPrivSep() error
	StopPrivSep()
}

type CmdBuilder struct {
	GitBin           string
	GitFlags         []string
	GPGBin           string
	GPGFlags         []string
	MakepkgFlags     []string
	MakepkgConfPath  string
	MakepkgBin       string
	SudoBin          string
	SudoFlags        []string
	SudoLoopEnabled  bool
	PacmanBin        string
	PacmanConfigPath string
	PacmanDBPath     string
	KeepSrc          bool
	PrivSepEnabled   bool
	Runner           Runner
	Log              *text.Logger

	privsepMu      sync.Mutex
	privsep        *privsep.Client
	privsepFailed  bool
	privsepPending map[*exec.Cmd]privsep.Request
}

func NewCmdBuilder(cfg *settings.Configuration, runner Runner, logger *text.Logger, dbPath string) *CmdBuilder {
	return &CmdBuilder{
		GitBin:           cfg.GitBin,
		GitFlags:         strings.Fields(cfg.GitFlags),
		GPGBin:           cfg.GpgBin,
		GPGFlags:         strings.Fields(cfg.GpgFlags),
		MakepkgFlags:     strings.Fields(cfg.MFlags),
		MakepkgConfPath:  cfg.MakepkgConf,
		MakepkgBin:       cfg.MakepkgBin,
		SudoBin:          cfg.SudoBin,
		SudoFlags:        strings.Fields(cfg.SudoFlags),
		SudoLoopEnabled:  cfg.SudoLoop,
		PacmanBin:        cfg.PacmanBin,
		PacmanConfigPath: cfg.PacmanConf,
		PacmanDBPath:     dbPath,
		KeepSrc:          cfg.KeepSrc,
		PrivSepEnabled:   cfg.PrivSep,
		Runner:           runner,
		Log:              logger,
	}
}

func (c *CmdBuilder) BuildGPGCmd(ctx context.Context, extraArgs ...string) *exec.Cmd {
	args := make([]string, len(c.GPGFlags), len(c.GPGFlags)+len(extraArgs))
	copy(args, c.GPGFlags)

	if len(extraArgs) > 0 {
		args = append(args, extraArgs...)
	}

	cmd := exec.CommandContext(ctx, c.GPGBin, args...)

	cmd = c.deElevateCommand(ctx, cmd)

	return cmd
}

func gitFilteredEnv() []string {
	var env []string

	for _, envVar := range os.Environ() {
		envKey, _, _ := strings.Cut(envVar, "=")
		if !gitDenyList.Contains(envKey) {
			env = append(env, envVar)
		}
	}

	env = append(env, "GIT_TERMINAL_PROMPT=0")

	return env
}

func (c *CmdBuilder) BuildGitCmd(ctx context.Context, dir string, extraArgs ...string) *exec.Cmd {
	args := make([]string, len(c.GitFlags), len(c.GitFlags)+len(extraArgs))
	copy(args, c.GitFlags)

	if dir != "" {
		args = append(args, "-C", dir)
	}

	if len(extraArgs) > 0 {
		args = append(args, extraArgs...)
	}

	cmd := exec.CommandContext(ctx, c.GitBin, args...)

	cmd.Env = gitFilteredEnv()

	cmd = c.deElevateCommand(ctx, cmd)

	return cmd
}

func (c *CmdBuilder) AddMakepkgFlag(flag string) {
	c.MakepkgFlags = append(c.MakepkgFlags, flag)
}

func (c *CmdBuilder) BuildMakepkgCmd(ctx context.Context, dir string, extraArgs ...string) *exec.Cmd {
	args := make([]string, len(c.MakepkgFlags), len(c.MakepkgFlags)+len(extraArgs))
	copy(args, c.MakepkgFlags)

	if c.MakepkgConfPath != "" {
		args = append(args, "--config", c.MakepkgConfPath)
	}

	if len(extraArgs) > 0 {
		args = append(args, extraArgs...)
	}

	cmd := exec.CommandContext(ctx, c.MakepkgBin, args...)
	cmd.Dir = dir

	cmd = c.deElevateCommand(ctx, cmd)
	cmd = c.noNewPrivsCommand(ctx, cmd)

	return cmd
}

// noNewPrivsCommand runs untrusted build code (makepkg + PKGBUILD) with the
// kernel's no_new_privs flag when privilege separation is on: setuid
// binaries such as sudo can then never grant root to a PKGBUILD. Go's
// SysProcAttr has no field for it, so setpriv(1) from util-linux is used.
func (c *CmdBuilder) noNewPrivsCommand(ctx context.Context, cmd *exec.Cmd) *exec.Cmd {
	if !c.PrivSepEnabled || os.Geteuid() == 0 {
		return cmd
	}

	setpriv, err := exec.LookPath("setpriv")
	if err != nil {
		c.Log.Warnln(gotext.Get("setpriv not found: building without no_new_privs"))
		return cmd
	}

	wrapped := exec.CommandContext(ctx, setpriv, append([]string{"--no-new-privs", "--"}, cmd.Args...)...)
	wrapped.Dir = cmd.Dir
	wrapped.Env = cmd.Env

	return wrapped
}

// deElevateCommand, `systemd-run` code based on pikaur.
func (c *CmdBuilder) deElevateCommand(ctx context.Context, cmd *exec.Cmd) *exec.Cmd {
	if os.Geteuid() != 0 {
		return cmd
	}

	ogCaller := ""
	if caller := os.Getenv("SUDO_USER"); caller != "" {
		ogCaller = caller
	} else if caller := os.Getenv("DOAS_USER"); caller != "" {
		ogCaller = caller
	}

	if userFound, err := user.Lookup(ogCaller); err == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
		uid64, errUid := strconv.ParseUint(userFound.Uid, 10, 32)
		gid64, errGid := strconv.ParseUint(userFound.Gid, 10, 32)
		if errUid == nil && errGid == nil {
			cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid64), Gid: uint32(gid64)}
			return cmd
		}
	}

	cmdArgs := []string{
		"--service-type=oneshot",
		"--pipe", "--wait", "--pty", "--quiet",
		"-p", "DynamicUser=yes",
		"-p", "CacheDirectory=yay",
		"-E", "HOME=/tmp",
	}

	if cmd.Dir != "" {
		cmdArgs = append(cmdArgs, "-p", fmt.Sprintf("WorkingDirectory=%s", cmd.Dir))
	}

	for _, envVarName := range [...]string{"http_proxy", "https_proxy", "ftp_proxy"} {
		if env := os.Getenv(envVarName); env != "" {
			cmdArgs = append(cmdArgs, "-E", fmt.Sprintf("%s=%s", envVarName, env))
		}
	}

	path, _ := exec.LookPath(cmd.Args[0])

	cmdArgs = append(cmdArgs, path)
	cmdArgs = append(cmdArgs, cmd.Args[1:]...)

	systemdCmd := exec.CommandContext(ctx, "systemd-run", cmdArgs...) // #nosec G702
	systemdCmd.Dir = cmd.Dir

	return systemdCmd
}

func (c *CmdBuilder) buildPrivilegeElevatorCommand(ctx context.Context, ogArgs []string) *exec.Cmd {
	if c.SudoBin == "su" {
		return exec.CommandContext(ctx, c.SudoBin, "-c", strings.Join(ogArgs, " "))
	}

	argArr := make([]string, 0, len(c.SudoFlags)+len(ogArgs))
	argArr = append(argArr, c.SudoFlags...)
	argArr = append(argArr, ogArgs...)

	return exec.CommandContext(ctx, c.SudoBin, argArr...)
}

func (c *CmdBuilder) BuildPacmanCmd(ctx context.Context, args *parser.Arguments, mode parser.TargetMode, noConfirm bool) *exec.Cmd {
	argArr := make([]string, 0, 32)
	needsRoot := args.NeedRoot(mode)

	argArr = append(argArr, c.PacmanBin)
	argArr = append(argArr, args.FormatGlobals()...)
	argArr = append(argArr, args.FormatArgs()...)

	if noConfirm {
		argArr = append(argArr, "--noconfirm")
	}

	argArr = append(argArr, "--config", c.PacmanConfigPath, "--")
	argArr = append(argArr, args.Targets...)

	if needsRoot {
		c.waitLock(c.PacmanDBPath)

		if os.Geteuid() != 0 {
			cmd := c.buildPrivilegeElevatorCommand(ctx, argArr)
			c.routeThroughBroker(cmd, args, noConfirm)

			return cmd
		}
	}

	return exec.CommandContext(ctx, argArr[0], argArr[1:]...)
}

// waitLock will lock yay checking the status of db.lck until it does not exist.
func (c *CmdBuilder) waitLock(dbPath string) {
	lockDBPath := filepath.Join(dbPath, "db.lck")
	if _, err := os.Stat(lockDBPath); err != nil {
		return
	}

	c.Log.Warnln(gotext.Get("%s is present.", lockDBPath))
	c.Log.Warn(gotext.Get("There may be another Pacman instance running. Waiting..."))

	for {
		time.Sleep(3 * time.Second)

		if _, err := os.Stat(lockDBPath); err != nil {
			c.Log.Println()

			return
		}
	}
}

// SudoLoop authenticates once and then keeps the sudo timestamp alive in the
// background. It fails safe: the old implementation retried `sudo -v` forever
// on failure, and every unanswered prompt was counted by pam_faillock until
// the account got locked. Now there is a single interactive attempt, and the
// background refresh uses `sudo -n`, which never prompts and therefore never
// produces a failed PAM authentication.
func (c *CmdBuilder) SudoLoop() error {
	if err := c.Show(exec.CommandContext(context.Background(), c.SudoBin, "-v")); err != nil {
		return fmt.Errorf("%s: %w", gotext.Get("sudo authentication failed"), err)
	}

	if err := c.refreshSudo(); err != nil {
		// e.g. timestamp_timeout=0: there is no cache to keep alive.
		c.Log.Warnln(gotext.Get("sudo does not cache credentials (timestamp_timeout=0?): sudoloop disabled, consider --privsep"))
		return nil
	}

	go c.sudoLoopBackground()

	return nil
}

func (c *CmdBuilder) sudoLoopBackground() {
	for {
		time.Sleep(SudoLoopDuration * time.Second)

		if err := c.refreshSudo(); err != nil {
			c.Log.Warnln(gotext.Get("sudo credentials expired: sudoloop stopped"))
			return
		}
	}
}

// refreshSudo extends the sudo timestamp without ever prompting.
func (c *CmdBuilder) refreshSudo() error {
	_, _, err := c.Runner.Capture(exec.CommandContext(context.Background(), c.SudoBin, "-n", "-v"))
	return err
}

// StartPrivSep launches the privileged broker (yas). It is the only point
// where the user is asked for a password during the run. A no-op when
// privilege separation is disabled, already running, or yay runs as root.
func (c *CmdBuilder) StartPrivSep() error {
	c.privsepMu.Lock()
	defer c.privsepMu.Unlock()

	return c.startPrivSepLocked()
}

func (c *CmdBuilder) startPrivSepLocked() error {
	if !c.PrivSepEnabled || c.privsep != nil || os.Geteuid() == 0 {
		return nil
	}

	if filepath.Base(c.SudoBin) == "su" {
		return errors.New(gotext.Get("--privsep is not supported with su; use sudo, doas or run0"))
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}

	client, err := privsep.Start(privsep.StartOptions{
		Executable: exe,
		PacmanBin:  c.PacmanBin,
		PacmanConf: c.PacmanConfigPath,
		Elevate: func(argv []string) *exec.Cmd {
			return c.buildPrivilegeElevatorCommand(context.Background(), argv)
		},
		ClearCredentials: c.clearElevatorCredentials,
	})
	if err != nil {
		c.privsepFailed = true
		return err
	}

	c.privsep = client
	c.privsepPending = map[*exec.Cmd]privsep.Request{}
	c.Log.Debugln("privileged broker started, pid", client.BrokerPID)

	return nil
}

// StopPrivSep closes the session; the broker exits when it sees EOF.
func (c *CmdBuilder) StopPrivSep() {
	c.privsepMu.Lock()
	defer c.privsepMu.Unlock()

	if c.privsep != nil {
		_ = c.privsep.Close()
		c.privsep = nil
	}
}

// clearElevatorCredentials drops any cached credential right after the
// broker started, so nothing else on this terminal (e.g. a PKGBUILD) can
// reuse it.
func (c *CmdBuilder) clearElevatorCredentials() {
	var args []string

	switch filepath.Base(c.SudoBin) {
	case "sudo":
		args = []string{"-k"}
	case "doas":
		args = []string{"-L"}
	default:
		return
	}

	_, _, _ = c.Runner.Capture(exec.CommandContext(context.Background(), c.SudoBin, args...))
}

// routeThroughBroker registers cmd (the classic `sudo pacman ...` command) to
// be executed by the broker instead. If the broker is unavailable the
// classic command is left untouched as a fallback.
func (c *CmdBuilder) routeThroughBroker(cmd *exec.Cmd, args *parser.Arguments, noConfirm bool) {
	if !c.PrivSepEnabled {
		return
	}

	c.privsepMu.Lock()
	defer c.privsepMu.Unlock()

	if c.privsep == nil && !c.privsepFailed {
		if err := c.startPrivSepLocked(); err != nil {
			c.Log.Warnln(gotext.Get("privileged broker unavailable, falling back to %s:", c.SudoBin), err)
		}
	}

	if c.privsep == nil {
		return
	}

	c.privsepPending[cmd] = brokerRequest(args, noConfirm)
}

// brokerRequest turns yay's parsed pacman arguments into a structured
// request. The broker re-validates every field; nothing here is trusted.
func brokerRequest(args *parser.Arguments, noConfirm bool) privsep.Request {
	req := privsep.Request{Op: args.Op}

	for name, opt := range args.Options {
		if name == "--" {
			continue
		}

		for _, value := range opt.Args {
			req.Flags = append(req.Flags, privsep.Flag{Name: name, Value: value})
		}
	}

	if noConfirm {
		req.Flags = append(req.Flags, privsep.Flag{Name: "noconfirm"})
	}

	for _, target := range args.Targets {
		// The broker runs in "/", so local package files must be absolute.
		if args.Op == "U" || args.Op == "upgrade" {
			if abs, err := filepath.Abs(target); err == nil && !strings.Contains(target, "://") {
				target = abs
			}
		}

		req.Targets = append(req.Targets, target)
	}

	return req
}

func (c *CmdBuilder) takeBrokerRequest(cmd *exec.Cmd) (privsep.Request, bool) {
	c.privsepMu.Lock()
	defer c.privsepMu.Unlock()

	if c.privsep == nil {
		return privsep.Request{}, false
	}

	req, ok := c.privsepPending[cmd]
	delete(c.privsepPending, cmd)

	return req, ok
}

func (c *CmdBuilder) Show(cmd *exec.Cmd) error {
	if req, ok := c.takeBrokerRequest(cmd); ok {
		c.Log.Debugln("running through privileged broker:", cmd.String())
		return c.privsep.Run(req)
	}

	return c.Runner.Show(cmd)
}

func (c *CmdBuilder) Capture(cmd *exec.Cmd) (stdout, stderr string, err error) {
	// Captured privileged commands keep the classic path.
	_, _ = c.takeBrokerRequest(cmd)

	return c.Runner.Capture(cmd)
}

func (c *CmdBuilder) GetKeepSrc() bool {
	return c.KeepSrc
}
