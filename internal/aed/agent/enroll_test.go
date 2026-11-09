package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestEnroll_HappyPath(t *testing.T) {
	var got enrollReq
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_ = json.NewEncoder(w).Encode(map[string]string{"cert_pem": "CERTPEM", "ca_pem": "CAPEM"})
	}))
	defer srv.Close()

	en, err := Enroll(context.Background(), srv.Client(), srv.URL, "vm1", "tok-123")
	if err != nil {
		t.Fatal(err)
	}
	if got.Token != "tok-123" || got.AgentID != "vm1" || !bytes.Contains([]byte(got.CSRPEM), []byte("CERTIFICATE REQUEST")) {
		t.Errorf("request to gateway wrong: %+v", got)
	}
	if string(en.CertPEM) != "CERTPEM" || string(en.CAPEM) != "CAPEM" {
		t.Errorf("materials wrong: %+v", en)
	}
	if !bytes.Contains(en.KeyPEM, []byte("PRIVATE KEY")) {
		t.Error("private key not generated")
	}
}

func TestEnroll_MissingCertErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"cert_pem": "", "ca_pem": ""})
	}))
	defer srv.Close()
	if _, err := Enroll(context.Background(), srv.Client(), srv.URL, "vm1", "tok"); err == nil {
		t.Error("a response missing the cert must error")
	}
}

func TestWriteConfig_ProtectedPerms(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "aed")
	en := &Enrolled{KeyPEM: []byte("K"), CertPEM: []byte("C"), CAPEM: []byte("A")}
	if err := WriteConfig(dir, en, "https://gw:8443", "vm1"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"agent.key", "agent.crt", "ca.crt", "agent.conf"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %v, want 0600", name, info.Mode().Perm())
		}
	}
}
