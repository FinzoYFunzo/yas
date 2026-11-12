// Package privsep implements privilege separation for yay ("yas": Yet another Sudo).
//
// Instead of invoking sudo once per privileged pacman call (and keeping a sudo
// timestamp alive with --sudoloop), yay launches a small privileged broker a
// single time. The broker then runs pacman on behalf of yay over a private
// unix socket, accepting only an allowlisted set of pacman operations.
//
// Properties:
//   - exactly one authentication per yay run, while the user is present;
//   - no reusable sudo credential is left on the terminal (sudo -k after launch),
//     so untrusted build code (PKGBUILDs) cannot silently obtain root;
//   - only the yay process that launched the broker can talk to it
//     (SO_PEERCRED check on both ends);
//   - the broker exits as soon as yay goes away (EOF on the socket).
package privsep

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ProtocolVersion is bumped whenever the wire format changes.
const ProtocolVersion = 1

// maxFrame bounds the size of a single frame to keep the root-side parser simple.
const maxFrame = 1 << 20

// Frame types. Each frame is: 1 byte type, 4 bytes big-endian length, payload.
const (
	frameHello   byte = 'H' // broker -> client: Hello (JSON)
	frameRequest byte = 'R' // client -> broker: Request (JSON)
	frameStdin   byte = 'I' // client -> broker: raw terminal input
	frameWinsize byte = 'W' // client -> broker: Winsize (JSON)
	frameOutput  byte = 'O' // broker -> client: raw terminal output
	frameExit    byte = 'X' // broker -> client: ExitStatus (JSON)
)

var errFrameTooLarge = errors.New("privsep: frame too large")

// Flag is a pacman option as yay parsed it, e.g. {Name: "y"} or
// {Name: "ignore", Value: "linux"}. The broker decides whether the option is
// allowed and whether it takes a value; the client never sends raw argv.
type Flag struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
}

// Request asks the broker to run one pacman operation.
type Request struct {
	Op      string   `json:"op"`
	Flags   []Flag   `json:"flags,omitempty"`
	Targets []string `json:"targets,omitempty"`
	Term    string   `json:"term,omitempty"`
	Rows    uint16   `json:"rows,omitempty"`
	Cols    uint16   `json:"cols,omitempty"`
}

// Hello is the first frame sent by the broker after the peer check succeeds.
type Hello struct {
	Version int `json:"version"`
	PID     int `json:"pid"`
}

// Winsize carries terminal size changes.
type Winsize struct {
	Rows uint16 `json:"rows"`
	Cols uint16 `json:"cols"`
}

// ExitStatus ends a Request. Error is set when the broker refused or failed
// to run pacman; Code mirrors pacman's exit code otherwise.
type ExitStatus struct {
	Code  int    `json:"code"`
	Error string `json:"error,omitempty"`
}

func writeFrame(w io.Writer, typ byte, payload []byte) error {
	if len(payload) > maxFrame {
		return errFrameTooLarge
	}

	buf := make([]byte, 5+len(payload))
	buf[0] = typ
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(payload)))
	copy(buf[5:], payload)

	_, err := w.Write(buf)

	return err
}

func writeJSON(w io.Writer, typ byte, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return err
	}

	return writeFrame(w, typ, payload)
}

func readFrame(r io.Reader) (typ byte, payload []byte, err error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}

	n := binary.BigEndian.Uint32(hdr[1:5])
	if n > maxFrame {
		return 0, nil, errFrameTooLarge
	}

	payload = make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, fmt.Errorf("privsep: truncated frame: %w", err)
	}

	return hdr[0], payload, nil
}
