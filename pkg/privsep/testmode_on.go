//go:build privseptest

package privsep

// insecureTestMode lets the broker run unprivileged and the client accept an
// unprivileged broker. It exists only to exercise the full binary (re-exec,
// socket handshake, pty relay) without root, using a fake pacman. Never ship
// a binary built with -tags privseptest.
const insecureTestMode = true
