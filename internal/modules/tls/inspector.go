package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"reconx/pkg/models"
)

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", v)
	}
}

// Inspect connects to the target host on port 443 and extracts TLS/SSL intelligence.
func Inspect(ctx context.Context, host string) (*models.TLSInfo, error) {
	addr := net.JoinHostPort(host, "443")
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		Config: &tls.Config{InsecureSkipVerify: true, ServerName: host},
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("TLS dial failed: %w", err)
	}
	defer conn.Close()

	tlsConn := conn.(*tls.Conn)
	state := tlsConn.ConnectionState()

	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates presented by %s", host)
	}
	cert := state.PeerCertificates[0]

	isSelfSigned := cert.Issuer.CommonName == cert.Subject.CommonName
	now := time.Now()
	daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)

	info := &models.TLSInfo{
		Host:            host,
		Port:            443,
		Issuer:          cert.Issuer.CommonName,
		Subject:         cert.Subject.CommonName,
		SANs:            cert.DNSNames,
		NotBefore:       cert.NotBefore,
		NotAfter:        cert.NotAfter,
		DaysUntilExpiry: daysLeft,
		IsExpired:       now.After(cert.NotAfter),
		TLSVersion:      tlsVersionName(state.Version),
		CipherSuite:     tls.CipherSuiteName(state.CipherSuite),
		IsSelfSigned:    isSelfSigned,
	}

	// Append IP SANs as strings
	for _, ip := range cert.IPAddresses {
		info.SANs = append(info.SANs, ip.String())
	}

	// Quick HSTS header check
	hstsCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(hstsCtx, http.MethodHead, "https://"+host, nil)
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	if resp, err := client.Do(req); err == nil {
		info.HSTSHeader = resp.Header.Get("Strict-Transport-Security")
		resp.Body.Close()
	}

	return info, nil
}
