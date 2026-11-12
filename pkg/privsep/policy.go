package privsep

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// PolicyError is returned when a request is outside the broker's allowlist.
type PolicyError struct {
	Reason string
}

func (e *PolicyError) Error() string {
	return "privsep policy: " + e.Reason
}

func deny(format string, a ...any) error {
	return &PolicyError{Reason: fmt.Sprintf(format, a...)}
}

type targetKind int

const (
	targetNone targetKind = iota
	targetNames
	targetPackageFiles
)

// flagSpec describes an allowed long option.
type flagSpec struct {
	takesValue bool
	validate   func(string) error
}

type opPolicy struct {
	letter  string            // pacman operation flag, e.g. "-S"
	shorts  map[string]string // short option -> long option, for this operation
	flags   map[string]flagSpec
	targets targetKind
	// requireTargets rejects an empty target list (pacman -U with no files).
	requireTargets bool
}

// forbidden lists options that redirect pacman to attacker-chosen paths or
// configuration. They are rejected explicitly so the error is informative.
var forbidden = map[string]string{
	"b": "dbpath", "dbpath": "dbpath",
	"r": "root", "root": "root",
	"sysroot":  "sysroot",
	"config":   "config",
	"cachedir": "cachedir",
	"gpgdir":   "gpgdir",
	"hookdir":  "hookdir",
	"logfile":  "logfile",
	"arch":     "arch",
}

var (
	noValue  = flagSpec{}
	anyValue = flagSpec{takesValue: true, validate: validateValue}
	askValue = flagSpec{takesValue: true, validate: func(v string) error {
		if _, err := strconv.ParseUint(v, 10, 16); err != nil {
			return deny("--ask expects a number, got %q", v)
		}
		return nil
	}}
	colorValue = flagSpec{takesValue: true, validate: func(v string) error {
		switch v {
		case "always", "never", "auto":
			return nil
		}
		return deny("--color expects always|never|auto, got %q", v)
	}}
	nameValue = flagSpec{takesValue: true, validate: validateName}
)

// globalFlags are accepted with every operation.
var globalFlags = map[string]flagSpec{
	"verbose":                  noValue,
	"debug":                    noValue,
	"noconfirm":                noValue,
	"confirm":                  noValue,
	"noprogressbar":            noValue,
	"disable-download-timeout": noValue,
	"color":                    colorValue,
	"ask":                      askValue,
}

var globalShorts = map[string]string{"v": "verbose"}

// transactionFlags are shared by -S, -U and -R.
var transactionFlags = map[string]flagSpec{
	"nodeps":           noValue,
	"dbonly":           noValue,
	"noscriptlet":      noValue,
	"assume-installed": nameValue,
}

// upgradeFlags are shared by -S and -U.
var upgradeFlags = map[string]flagSpec{
	"asdeps":       noValue,
	"asexplicit":   noValue,
	"needed":       noValue,
	"downloadonly": noValue,
	"ignore":       nameValue,
	"ignoregroup":  nameValue,
	"overwrite":    anyValue,
}

func merge(maps ...map[string]flagSpec) map[string]flagSpec {
	out := map[string]flagSpec{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}

	return out
}

var policies = map[string]opPolicy{
	"S": {
		letter: "-S",
		shorts: map[string]string{"y": "refresh", "u": "sysupgrade", "c": "clean", "d": "nodeps", "w": "downloadonly", "q": "quiet"},
		flags: merge(transactionFlags, upgradeFlags, map[string]flagSpec{
			"refresh": noValue, "sysupgrade": noValue, "clean": noValue, "quiet": noValue,
		}),
		targets: targetNames,
	},
	"U": {
		letter:         "-U",
		shorts:         map[string]string{"d": "nodeps", "w": "downloadonly"},
		flags:          merge(transactionFlags, upgradeFlags),
		targets:        targetPackageFiles,
		requireTargets: true,
	},
	"R": {
		letter: "-R",
		shorts: map[string]string{"c": "cascade", "d": "nodeps", "n": "nosave", "s": "recursive", "u": "unneeded"},
		flags: merge(transactionFlags, map[string]flagSpec{
			"cascade": noValue, "nosave": noValue, "recursive": noValue, "unneeded": noValue,
		}),
		targets:        targetNames,
		requireTargets: true,
	},
	"D": {
		letter:         "-D",
		shorts:         map[string]string{"q": "quiet"},
		flags:          map[string]flagSpec{"asdeps": noValue, "asexplicit": noValue, "quiet": noValue},
		targets:        targetNames,
		requireTargets: true,
	},
	"F": {
		letter:  "-F",
		shorts:  map[string]string{"y": "refresh", "q": "quiet"},
		flags:   map[string]flagSpec{"refresh": noValue, "quiet": noValue},
		targets: targetNone,
	},
	"Q": {
		letter:  "-Q",
		shorts:  map[string]string{"k": "check", "q": "quiet"},
		flags:   map[string]flagSpec{"check": noValue, "quiet": noValue},
		targets: targetNames,
	},
}

var opAliases = map[string]string{
	"S": "S", "sync": "S",
	"U": "U", "upgrade": "U",
	"R": "R", "remove": "R",
	"D": "D", "database": "D",
	"F": "F", "files": "F",
	"Q": "Q", "query": "Q",
}

// Package names, groups, "repo/name" and version constraints ("foo>=1:2.0-1").
// The first character can never be '-', so a target can't be read as an option.
var nameRe = regexp.MustCompile(`^[A-Za-z0-9@_+.][A-Za-z0-9@._+:<>=/-]*$`)

// Files produced by makepkg / stored in the pacman cache.
var pkgFileRe = regexp.MustCompile(`\.pkg\.tar(\.(zst|xz|gz|bz2|lz4|lrz|lzo|Z))?$`)

func validateValue(v string) error {
	if len(v) > 4096 {
		return deny("option value too long")
	}

	if strings.ContainsAny(v, "\x00\n\r") {
		return deny("option value contains control characters")
	}

	return nil
}

func validateName(v string) error {
	if len(v) == 0 || len(v) > 256 || !nameRe.MatchString(v) || strings.Contains(v, "..") {
		return deny("invalid package name %q", v)
	}

	return nil
}

// validatePackageFile accepts only local, regular package files. URLs are
// rejected so that root never downloads anything on behalf of the client.
func validatePackageFile(p string) error {
	if strings.Contains(p, "://") {
		return deny("remote targets are not allowed: %q", p)
	}

	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return deny("package path must be absolute and clean: %q", p)
	}

	if !pkgFileRe.MatchString(p) {
		return deny("not a package file: %q", p)
	}

	fi, err := os.Lstat(p)
	if err != nil {
		return deny("cannot stat %q: %v", p, err)
	}

	if !fi.Mode().IsRegular() {
		return deny("package must be a regular file (no symlinks): %q", p)
	}

	return nil
}

// BuildArgv validates req against the allowlist and returns the exact argv
// the broker will execute. pacmanBin and pacmanConf come from the broker's
// own command line (fixed at launch, when the user authenticated), never
// from the request.
func BuildArgv(pacmanBin, pacmanConf string, req *Request) ([]string, error) {
	opKey, ok := opAliases[req.Op]
	if !ok {
		return nil, deny("operation %q is not allowed", req.Op)
	}

	pol := policies[opKey]
	argv := []string{pacmanBin, "--config", pacmanConf, pol.letter}

	for _, f := range req.Flags {
		if name, bad := forbidden[f.Name]; bad {
			return nil, deny("option --%s is forbidden", name)
		}

		long := f.Name
		if l, ok := pol.shorts[f.Name]; ok {
			long = l
		} else if l, ok := globalShorts[f.Name]; ok {
			long = l
		}

		spec, ok := pol.flags[long]
		if !ok {
			spec, ok = globalFlags[long]
		}

		if !ok {
			return nil, deny("option %q is not allowed with %s", f.Name, pol.letter)
		}

		if !spec.takesValue {
			if f.Value != "" {
				return nil, deny("option --%s does not take a value", long)
			}

			argv = append(argv, "--"+long)

			continue
		}

		if err := spec.validate(f.Value); err != nil {
			return nil, err
		}

		// "--name=value" is unambiguous even if value starts with '-'.
		argv = append(argv, "--"+long+"="+f.Value)
	}

	if len(req.Targets) > 0 && pol.targets == targetNone {
		return nil, deny("%s does not take targets", pol.letter)
	}

	if len(req.Targets) == 0 && pol.requireTargets {
		return nil, deny("%s requires targets", pol.letter)
	}

	for _, t := range req.Targets {
		var err error
		if pol.targets == targetPackageFiles {
			err = validatePackageFile(t)
		} else {
			err = validateName(t)
		}

		if err != nil {
			return nil, err
		}
	}

	argv = append(argv, "--")
	argv = append(argv, req.Targets...)

	return argv, nil
}
