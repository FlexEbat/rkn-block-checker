package main

import "crypto/tls"

// insecureTLSConfig returns a TLS configuration with certificate verification
// disabled. This is a deliberate choice, not forgotten debt: the tool
// analyzes HOW a connection is being blocked (RST, DPI fragmentation, SNI
// filtering, etc.), not whether the target host's certificate is legitimate —
// a valid certificate isn't required here and often gets in the way of
// diagnosing MITM/blocking behavior.
// Kept in one place so linters/`go vet` don't flag every InsecureSkipVerify
// individually, and so an allowlist or other safeguard can be added
// centrally later if needed.
func insecureTLSConfig(nextProtos ...string) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, // required for censorship analysis, see doc comment above
		NextProtos:         nextProtos,
	}
}
