package intel

import (
	"strings"
	"testing"
	"time"

	"reconx/internal/providers/crtsh"
	"reconx/pkg/models"
)

func TestParseSPF(t *testing.T) {
	spf := ParseSPF([]string{"google-site-verification=abc", "v=spf1 include:_spf.google.com include:sendgrid.net ip4:203.0.113.0/24 mx -all"})
	if !spf.Present || !spf.Valid {
		t.Fatalf("expected valid SPF, got %+v", spf)
	}
	if spf.All != "-all" || !strings.HasPrefix(spf.Policy, "Hard fail") {
		t.Errorf("all/policy = %q / %q", spf.All, spf.Policy)
	}
	if spf.LookupCount != 3 { // include, include, mx
		t.Errorf("lookup count = %d, want 3", spf.LookupCount)
	}
	if strings.Join(spf.Senders, ",") != "Google Workspace,SendGrid" {
		t.Errorf("senders = %v", spf.Senders)
	}
	if len(spf.Mechanisms) != 5 || spf.Mechanisms[2].Type != "ip4" || spf.Mechanisms[2].Value != "203.0.113.0/24" {
		t.Errorf("mechanisms = %+v", spf.Mechanisms)
	}
}

func TestParseSPFProblems(t *testing.T) {
	multi := ParseSPF([]string{"v=spf1 -all", "v=spf1 +all"})
	if multi.Valid || multi.RecordCount != 2 {
		t.Errorf("multiple SPF records must be invalid: %+v", multi)
	}
	plus := ParseSPF([]string{"v=spf1 +all"})
	if plus.All != "+all" || len(plus.Issues) == 0 {
		t.Errorf("+all should be flagged: %+v", plus)
	}
	bad := ParseSPF([]string{"v=spf1 bogus:x ~all"})
	if bad.Valid {
		t.Errorf("unknown mechanism should invalidate SPF")
	}
	redir := ParseSPF([]string{"v=spf1 redirect=_spf.example.net"})
	if redir.Redirect != "_spf.example.net" || redir.LookupCount != 1 {
		t.Errorf("redirect parse: %+v", redir)
	}
	if none := ParseSPF([]string{"hello"}); none.Present {
		t.Errorf("non-SPF TXT detected as SPF")
	}
}

func TestParseDMARC(t *testing.T) {
	d := ParseDMARC([]string{"v=DMARC1; p=quarantine; sp=reject; pct=50; rua=mailto:a@x.com,mailto:b@x.com; adkim=s"})
	if !d.Valid || d.Policy != "quarantine" || d.SubdomainPolicy != "reject" || d.Pct != 50 {
		t.Fatalf("unexpected: %+v", d)
	}
	if len(d.RUA) != 2 || d.ADKIM != "strict" || d.ASPF != "relaxed" {
		t.Errorf("tags: %+v", d)
	}
	none := ParseDMARC([]string{"v=DMARC1; p=none"})
	if !strings.Contains(none.Posture, "Monitoring only") || none.SubdomainPolicy != "none" {
		t.Errorf("p=none posture: %+v", none)
	}
	missing := ParseDMARC(nil)
	if missing.Present || !strings.HasPrefix(missing.Posture, "Missing") {
		t.Errorf("missing: %+v", missing)
	}
	if inv := ParseDMARC([]string{"v=DMARC1; rua=mailto:x@y"}); inv.Valid {
		t.Errorf("record without p= must be invalid")
	}
}

func TestParseDKIM(t *testing.T) {
	// 1024-bit RSA SubjectPublicKeyInfo.
	key := "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDOCTHqIwq5d2c3sR8+5SC2D7Vv2O1ac5XUk2B+7qD7r3D6yH8hY4N8h3c5e6Qf0n6k2rk3V7x9yQf0f3d0Q7T7hH8c2b0d3vY9t9w3k5Q6Yq1Q2c3f4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0fQIDAQAB"
	s := ParseDKIM("google", "v=DKIM1; k=rsa; p="+key)
	if s.Revoked || s.KeyType != "rsa" {
		t.Errorf("unexpected: %+v", s)
	}
	if rev := ParseDKIM("old", "v=DKIM1; p="); !rev.Revoked {
		t.Errorf("empty p= means revoked")
	}
}

func TestMTASTSAndTLSRPT(t *testing.T) {
	m := ParseMTASTS([]string{"v=STSv1; id=20240101T000000"})
	if !m.Present || m.ID != "20240101T000000" {
		t.Errorf("mta-sts: %+v", m)
	}
	r := ParseTLSRPT([]string{"v=TLSRPTv1; rua=mailto:tls@example.com"})
	if !r.Present || len(r.RUA) != 1 {
		t.Errorf("tls-rpt: %+v", r)
	}
}

func TestScoreEmailExcludesInconclusiveDKIM(t *testing.T) {
	es := &models.EmailSecurity{
		SPF:   ParseSPF([]string{"v=spf1 -all"}),
		DMARC: ParseDMARC([]string{"v=DMARC1; p=reject; rua=mailto:x@y"}),
	}
	ScoreEmail(es)
	if es.MaxScore != 80 || es.Score != 55 {
		t.Errorf("score %d/%d, want 55/80 (DKIM not counted)", es.Score, es.MaxScore)
	}
}

func TestParseCAA(t *testing.T) {
	c := ParseCAA([]models.CAARecord{
		{Tag: "issue", Value: "letsencrypt.org"},
		{Tag: "issuewild", Value: "digicert.com"},
		{Tag: "iodef", Value: "mailto:sec@example.com"},
	})
	if c.Posture != "restrictive" || len(c.Issue) != 1 || len(c.Iodef) != 1 {
		t.Fatalf("unexpected: %+v", c)
	}
	inconsistent := false
	for _, n := range c.Notes {
		if strings.Contains(n, "inconsistent") {
			inconsistent = true
		}
	}
	if !inconsistent {
		t.Errorf("issuewild CA outside issue list should be noted: %v", c.Notes)
	}
	if none := ParseCAA(nil); none.Present || none.Posture != "none" {
		t.Errorf("no CAA: %+v", none)
	}
}

func TestClassify(t *testing.T) {
	cases := map[string]string{
		"api.example.com":         "API",
		"staging-api.example.com": "Staging",
		"mail.example.com":        "Email",
		"docs.example.com":        "Documentation",
		"vpn2.example.com":        "VPN / Remote Access",
		"jenkins.ci.example.com":  "CI/CD",
		"admin.example.com":       "Administrative",
		"winremote.example.com":   "VPN / Remote Access",
		"helpdesk.example.com":    "Documentation",
		"zzz.example.com":         "Unknown",
		"example.com":             "Web (apex)",
	}
	for host, want := range cases {
		if got, _ := Classify(host, "example.com"); got != want {
			t.Errorf("Classify(%s) = %s, want %s", host, got, want)
		}
	}
	if _, ind := Classify("old-admin.example.com", "example.com"); strings.Join(ind, ",") != "old,admin" {
		t.Errorf("indicators = %v", ind)
	}
}

func TestConfidenceAndRecency(t *testing.T) {
	now := time.Now()
	old := now.AddDate(-5, 0, 0)
	recent := now.AddDate(0, 0, -3)

	waybackOnly := &models.HostIntel{Evidence: []models.SourceEvidence{{Source: "wayback", LastSeen: &old}}, DNSStatus: "nxdomain", LastSeen: &old}
	ScoreConfidence(waybackOnly, now)
	ClassifyRecency(waybackOnly, now)

	strong := &models.HostIntel{Evidence: []models.SourceEvidence{{Source: "crtsh", LastSeen: &recent}, {Source: "alienvault", LastSeen: &recent}}, DNSStatus: "resolves"}
	ScoreConfidence(strong, now)
	ClassifyRecency(strong, now)

	if waybackOnly.Confidence >= strong.Confidence || waybackOnly.ConfidenceLevel != "low" || strong.ConfidenceLevel != "high" {
		t.Errorf("confidence: wayback-only %d (%s), strong %d (%s)", waybackOnly.Confidence, waybackOnly.ConfidenceLevel, strong.Confidence, strong.ConfidenceLevel)
	}
	if waybackOnly.Recency != "stale" || strong.Recency != "current" {
		t.Errorf("recency: %s / %s", waybackOnly.Recency, strong.Recency)
	}
}

func TestProviderMatching(t *testing.T) {
	if r := MatchCNAME("d111111abcdef8.cloudfront.net"); r == nil || r.Name != "Amazon CloudFront" {
		t.Errorf("cloudfront: %+v", r)
	}
	if r := MatchCNAME("bucket.s3-website-us-east-1.amazonaws.com"); r == nil || r.Name != "AWS S3" {
		t.Errorf("s3 website: %+v", r)
	}
	if r := MatchIP("AS13335 Cloudflare, Inc."); r == nil || r.Name != "Cloudflare" {
		t.Errorf("asn: %+v", r)
	}
	if r := MatchIP("AS99999", "Amazon.com, Inc."); r == nil || r.Name != "AWS" {
		t.Errorf("org: %+v", r)
	}
	if r := MatchMX("aspmx.l.google.com"); r == nil || r.Name != "Google Workspace" {
		t.Errorf("mx: %+v", r)
	}
	if r := MatchNS("ns-123.awsdns-45.com"); r == nil || r.Name != "AWS Route 53" {
		t.Errorf("ns: %+v", r)
	}
}

func TestBuildCertificates(t *testing.T) {
	now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	entries := []crtsh.Entry{
		// precertificate and certificate share issuer+serial → one cert
		{ID: 1, IssuerName: "C=US, O=Let's Encrypt, CN=R3", SerialNumber: "aa", CommonName: "example.com",
			NameValue: "example.com\nwww.example.com\nstaging.example.com", NotBefore: "2026-09-20T00:00:00", NotAfter: "2026-10-10T00:00:00", EntryTimestamp: "2026-09-20T01:00:00.123"},
		{ID: 2, IssuerName: "C=US, O=Let's Encrypt, CN=R3", SerialNumber: "aa", CommonName: "example.com",
			NameValue: "example.com", NotBefore: "2026-09-20T00:00:00", NotAfter: "2026-10-10T00:00:00", EntryTimestamp: "2026-09-20T00:30:00"},
		{ID: 3, IssuerName: "C=US, O=DigiCert Inc, CN=DigiCert TLS", SerialNumber: "bb", CommonName: "*.example.com",
			NameValue: "*.example.com", NotBefore: "2024-01-01T00:00:00", NotAfter: "2025-01-01T00:00:00"},
	}
	certs, sum, hostCerts := BuildCertificates(entries, "example.com", now)
	if len(certs) != 2 || sum.Total != 2 {
		t.Fatalf("expected 2 deduplicated certs, got %d", len(certs))
	}
	if certs[0].ExpiryStatus != "lt7" || certs[1].ExpiryStatus != "expired" {
		t.Errorf("expiry: %s, %s", certs[0].ExpiryStatus, certs[1].ExpiryStatus)
	}
	if !certs[1].Wildcard || certs[0].IssuerOrg != "Let's Encrypt" {
		t.Errorf("wildcard/issuer: %+v", certs)
	}
	if strings.Join(certs[0].Indicators, ",") != "staging" {
		t.Errorf("indicators: %v", certs[0].Indicators)
	}
	if sum.Expired != 1 || sum.Lt7 != 1 || hostCerts["example.com"] != 2 {
		t.Errorf("summary %+v hostCerts %v", sum, hostCerts)
	}
}

func TestCymruName(t *testing.T) {
	if got := cymruName("8.8.4.4"); got != "4.4.8.8.origin.asn.cymru.com" {
		t.Errorf("v4: %s", got)
	}
	if got := cymruName("2001:db8::1"); !strings.HasPrefix(got, "1.0.0.0.") || !strings.HasSuffix(got, ".8.b.d.0.1.0.0.2.origin6.asn.cymru.com") {
		t.Errorf("v6: %s", got)
	}
	if cymruName("10.0.0.1") != "" {
		t.Errorf("private IPs must be skipped")
	}
}

func TestInterestPrioritisesExposedSensitiveHosts(t *testing.T) {
	gitlab := &models.HostIntel{Role: "CI/CD", Indicators: []string{"gitlab"}, DNSStatus: "resolves", ConfidenceLevel: "high"}
	ScoreInterest(gitlab, false)
	zabbix := &models.HostIntel{Role: "Monitoring", DNSStatus: "resolves", ConfidenceLevel: "high"}
	ScoreInterest(zabbix, false)
	gone := &models.HostIntel{Role: "VPN / Remote Access", DNSStatus: "nxdomain", ConfidenceLevel: "medium"}
	ScoreInterest(gone, false)
	plain := &models.HostIntel{Role: "Web", DNSStatus: "resolves", ConfidenceLevel: "high"}
	ScoreInterest(plain, false)
	if gitlab.Interest != "high" || zabbix.Interest != "high" || gone.Interest != "medium" || plain.Interest != "low" {
		t.Errorf("interest: gitlab=%s zabbix=%s gone=%s plain=%s", gitlab.Interest, zabbix.Interest, gone.Interest, plain.Interest)
	}
}
