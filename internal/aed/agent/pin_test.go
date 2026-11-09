package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// makeCAAndLeaf returns a CA (DER) and a TLS server certificate presenting the
// chain [leaf, CA], the leaf signed by the CA.
func makeCAAndLeaf(t *testing.T) (caDER []byte, serverCert tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "AED Test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
	caDER, err = x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"127.0.0.1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return caDER, tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}
}

func tlsServer(t *testing.T, cert tls.Certificate) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	return srv
}

func TestPinnedClient_AcceptsMatchingCA(t *testing.T) {
	caDER, cert := makeCAAndLeaf(t)
	srv := tlsServer(t, cert)
	defer srv.Close()
	sum := sha256.Sum256(caDER)
	resp, err := PinnedClient(hex.EncodeToString(sum[:]), 5*time.Second).Get(srv.URL)
	if err != nil {
		t.Fatalf("pinned client should accept the matching CA: %v", err)
	}
	_ = resp.Body.Close()
}

func TestPinnedClient_RejectsWrongFingerprint(t *testing.T) {
	_, cert := makeCAAndLeaf(t)
	srv := tlsServer(t, cert)
	defer srv.Close()
	wrong := strings.Repeat("ab", 32) // a valid-length but non-matching fingerprint
	if _, err := PinnedClient(wrong, 5*time.Second).Get(srv.URL); err == nil {
		t.Fatal("pinned client must reject a server whose CA fingerprint does not match")
	}
}
