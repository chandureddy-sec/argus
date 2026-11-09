package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
)

type enrollReq struct {
	Token   string `json:"token"`
	CSRPEM  string `json:"csr_pem"`
	AgentID string `json:"agent_id"`
}

type enrollResp struct {
	CertPEM string `json:"cert_pem"`
	CAPEM   string `json:"ca_pem"`
}

// Enrolled holds the materials produced by enrolment, written to the config dir.
type Enrolled struct {
	KeyPEM  []byte
	CSRPEM  []byte
	CertPEM []byte
	CAPEM   []byte
}

// generateCSR makes an EC P-256 key and a CSR with the agent id as the subject
// common name. The private key never leaves the host.
func generateCSR(agentID string) (keyPEM, csrPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: agentID}}, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return keyPEM, csrPEM, nil
}

// Enroll generates a key/CSR and exchanges the single-use token for a signed
// client certificate at the gateway's /aed/enroll, over the supplied client
// (which must pin the CA fingerprint). It does not touch the filesystem.
func Enroll(ctx context.Context, client *http.Client, gatewayURL, agentID, token string) (*Enrolled, error) {
	keyPEM, csrPEM, err := generateCSR(agentID)
	if err != nil {
		return nil, fmt.Errorf("generate CSR: %w", err)
	}
	body, err := json.Marshal(enrollReq{Token: token, CSRPEM: string(csrPEM), AgentID: agentID})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, gatewayURL+"/aed/enroll", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("enroll request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("enroll: gateway returned %d", resp.StatusCode)
	}
	var er enrollResp
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		return nil, fmt.Errorf("enroll: bad response: %w", err)
	}
	if er.CertPEM == "" || er.CAPEM == "" {
		return nil, fmt.Errorf("enroll: response missing cert or CA")
	}
	return &Enrolled{KeyPEM: keyPEM, CSRPEM: csrPEM, CertPEM: []byte(er.CertPEM), CAPEM: []byte(er.CAPEM)}, nil
}

// WriteConfig writes the enrolment materials and an agent.conf into dir with
// owner-only permissions (0600 files in a 0700 dir). The private key is written
// 0600 and never logged.
func WriteConfig(dir string, e *Enrolled, gatewayURL, agentID string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	files := []struct {
		name string
		data []byte
	}{
		{"agent.key", e.KeyPEM},
		{"agent.crt", e.CertPEM},
		{"ca.crt", e.CAPEM},
		{"agent.conf", []byte(fmt.Sprintf("gateway_url=%s\nagent_id=%s\n", gatewayURL, agentID))},
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f.name), f.data, 0o600); err != nil {
			return err
		}
	}
	return nil
}
