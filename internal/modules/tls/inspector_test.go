package tls

import (
	"crypto/tls"
	"testing"
)

func TestTLSVersionName(t *testing.T) {
	cases := map[uint16]string{
		tls.VersionTLS10: "TLS 1.0",
		tls.VersionTLS11: "TLS 1.1",
		tls.VersionTLS12: "TLS 1.2",
		tls.VersionTLS13: "TLS 1.3",
	}
	for v, want := range cases {
		if got := tlsVersionName(v); got != want {
			t.Errorf("tlsVersionName(0x%04x) = %q, want %q", v, got, want)
		}
	}
	if got := tlsVersionName(0x0000); got == "" {
		t.Error("unknown version should return a non-empty label")
	}
}
