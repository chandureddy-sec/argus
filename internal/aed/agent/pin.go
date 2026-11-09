package agent

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// pinnedVerify accepts the server only when the presented chain contains a CA
// whose SHA-256 (DER) fingerprint equals want AND the server leaf verifies
// against that CA. It is used for the single enrollment call, before the agent
// has the CA on disk — so the agent trusts the Argus CA by fingerprint, not by
// the host's trust store.
func pinnedVerify(want string) func(tls.ConnectionState) error {
	want = strings.ToLower(strings.ReplaceAll(want, ":", ""))
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return fmt.Errorf("no server certificate presented")
		}
		var pinned *x509.Certificate
		for _, c := range cs.PeerCertificates {
			sum := sha256.Sum256(c.Raw)
			if hex.EncodeToString(sum[:]) == want {
				pinned = c
				break
			}
		}
		if pinned == nil {
			return fmt.Errorf("server CA fingerprint does not match the pinned value")
		}
		roots := x509.NewCertPool()
		roots.AddCert(pinned)
		inter := x509.NewCertPool()
		for _, c := range cs.PeerCertificates[1:] {
			inter.AddCert(c)
		}
		if _, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter}); err != nil {
			return fmt.Errorf("server certificate does not chain to the pinned CA: %w", err)
		}
		return nil
	}
}

// PinnedClient builds an http.Client that trusts the gateway only when its CA
// chain matches the pinned SHA-256 fingerprint. The default verifier is disabled
// and replaced by our own pinned check (VerifyConnection); this is cert pinning,
// not a disabled check. The agent uses MTLSClient after enrolment.
func PinnedClient(caFingerprint string, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// Disable the default name/trust check and pin by CA fingerprint
				// instead (see pinnedVerify). G402 is intentional here.
				InsecureSkipVerify: true, //nolint:gosec
				VerifyConnection:   pinnedVerify(caFingerprint),
				MinVersion:         tls.VersionTLS12,
			},
		},
	}
}
