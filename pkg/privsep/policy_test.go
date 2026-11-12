package privsep

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildArgvAllowed(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pkg := filepath.Join(dir, "foo-1.0-1-x86_64.pkg.tar.zst")
	require.NoError(t, os.WriteFile(pkg, []byte("x"), 0o644))

	tests := []struct {
		name string
		req  Request
		want []string
	}{
		{
			name: "sysupgrade with short flags",
			req:  Request{Op: "S", Flags: []Flag{{Name: "y"}, {Name: "u"}, {Name: "noconfirm"}}},
			want: []string{"/usr/bin/pacman", "--config", "/etc/pacman.conf", "-S", "--refresh", "--sysupgrade", "--noconfirm", "--"},
		},
		{
			name: "sync with value flags and repo target",
			req:  Request{Op: "sync", Flags: []Flag{{Name: "needed"}, {Name: "ignore", Value: "linux"}}, Targets: []string{"extra/htop", "glibc>=2.40"}},
			want: []string{"/usr/bin/pacman", "--config", "/etc/pacman.conf", "-S", "--needed", "--ignore=linux", "--", "extra/htop", "glibc>=2.40"},
		},
		{
			name: "install local package (downgrade)",
			req:  Request{Op: "U", Flags: []Flag{{Name: "asdeps"}}, Targets: []string{pkg}},
			want: []string{"/usr/bin/pacman", "--config", "/etc/pacman.conf", "-U", "--asdeps", "--", pkg},
		},
		{
			name: "remove make dependencies: -u means unneeded for -R",
			req:  Request{Op: "R", Flags: []Flag{{Name: "s"}, {Name: "u"}}, Targets: []string{"go"}},
			want: []string{"/usr/bin/pacman", "--config", "/etc/pacman.conf", "-R", "--recursive", "--unneeded", "--", "go"},
		},
		{
			name: "mark as dependency",
			req:  Request{Op: "D", Flags: []Flag{{Name: "asdeps"}}, Targets: []string{"go"}},
			want: []string{"/usr/bin/pacman", "--config", "/etc/pacman.conf", "-D", "--asdeps", "--", "go"},
		},
		{
			name: "global options",
			req:  Request{Op: "S", Flags: []Flag{{Name: "v"}, {Name: "color", Value: "never"}, {Name: "ask", Value: "4"}}},
			want: []string{"/usr/bin/pacman", "--config", "/etc/pacman.conf", "-S", "--verbose", "--color=never", "--ask=4", "--"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := BuildArgv("/usr/bin/pacman", "/etc/pacman.conf", &tc.req)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestBuildArgvDenied(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pkg := filepath.Join(dir, "foo-1.0-1-x86_64.pkg.tar.zst")
	require.NoError(t, os.WriteFile(pkg, []byte("x"), 0o644))

	link := filepath.Join(dir, "link-1.0-1-x86_64.pkg.tar.zst")
	require.NoError(t, os.Symlink(pkg, link))

	notPkg := filepath.Join(dir, "evil.sh")
	require.NoError(t, os.WriteFile(notPkg, []byte("x"), 0o755))

	dirPkg := filepath.Join(dir, "dir.pkg.tar.zst")
	require.NoError(t, os.Mkdir(dirPkg, 0o755))

	tests := []struct {
		name string
		req  Request
	}{
		{"operation not allowed (deptest)", Request{Op: "T"}},
		{"unknown operation", Request{Op: "X"}},
		{"--root redirects the install", Request{Op: "S", Flags: []Flag{{Name: "root", Value: "/tmp/x"}}}},
		{"-r short for root", Request{Op: "S", Flags: []Flag{{Name: "r", Value: "/tmp/x"}}}},
		{"--dbpath", Request{Op: "S", Flags: []Flag{{Name: "b", Value: "/tmp/db"}}}},
		{"--config from the client", Request{Op: "S", Flags: []Flag{{Name: "config", Value: "/tmp/evil.conf"}}}},
		{"--hookdir runs attacker hooks as root", Request{Op: "U", Flags: []Flag{{Name: "hookdir", Value: "/tmp/hooks"}}, Targets: []string{pkg}}},
		{"--sysroot", Request{Op: "S", Flags: []Flag{{Name: "sysroot", Value: "/tmp"}}}},
		{"--gpgdir", Request{Op: "S", Flags: []Flag{{Name: "gpgdir", Value: "/tmp"}}}},
		{"--logfile", Request{Op: "S", Flags: []Flag{{Name: "logfile", Value: "/etc/shadow"}}}},
		{"unknown option", Request{Op: "S", Flags: []Flag{{Name: "exec", Value: "sh"}}}},
		{"option from another operation", Request{Op: "D", Flags: []Flag{{Name: "cascade"}}, Targets: []string{"x"}}},
		{"value on a boolean option", Request{Op: "S", Flags: []Flag{{Name: "needed", Value: "x"}}}},
		{"newline in value", Request{Op: "S", Flags: []Flag{{Name: "overwrite", Value: "a\nb"}}}},
		{"--ask not numeric", Request{Op: "S", Flags: []Flag{{Name: "ask", Value: "yes"}}}},
		{"--color invalid", Request{Op: "S", Flags: []Flag{{Name: "color", Value: "rainbow"}}}},
		{"target looks like an option", Request{Op: "S", Targets: []string{"--root=/tmp"}}},
		{"target with path traversal", Request{Op: "R", Targets: []string{"../../etc"}}},
		{"target with shell metacharacters", Request{Op: "S", Targets: []string{"foo;rm"}}},
		{"-U from a URL (root would download)", Request{Op: "U", Targets: []string{"https://evil.example/x.pkg.tar.zst"}}},
		{"-U relative path", Request{Op: "U", Targets: []string{"foo-1.0-1-x86_64.pkg.tar.zst"}}},
		{"-U non-clean path", Request{Op: "U", Targets: []string{dir + "/./foo-1.0-1-x86_64.pkg.tar.zst"}}},
		{"-U symlink", Request{Op: "U", Targets: []string{link}}},
		{"-U not a package", Request{Op: "U", Targets: []string{notPkg}}},
		{"-U directory", Request{Op: "U", Targets: []string{dirPkg}}},
		{"-U missing file", Request{Op: "U", Targets: []string{filepath.Join(dir, "nope-1-1-any.pkg.tar.zst")}}},
		{"-U without targets", Request{Op: "U"}},
		{"-R without targets", Request{Op: "R"}},
		{"-F with targets", Request{Op: "F", Flags: []Flag{{Name: "y"}}, Targets: []string{"x"}}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			argv, err := BuildArgv("/usr/bin/pacman", "/etc/pacman.conf", &tc.req)
			require.Error(t, err, "argv would have been %v", argv)

			var perr *PolicyError
			assert.ErrorAs(t, err, &perr)
		})
	}
}
