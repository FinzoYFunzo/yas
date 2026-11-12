//go:build !privseptest

package privsep

// insecureTestMode is only true in binaries built with -tags privseptest.
const insecureTestMode = false
