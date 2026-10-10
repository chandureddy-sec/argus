package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"reconx/pkg/models"
)

func threatReport() *models.ScanReport {
	return &models.ScanReport{
		Target:    &models.Target{Value: "example.com", Type: models.TargetTypeDomain},
		Timestamp: time.Now().UTC(),
		ThreatIntel: &models.ThreatIntel{
			Server: "http://127.0.0.1:8000", TLP: "TLP:GREEN", Status: "partial", CheckedAt: time.Now().UTC(),
			Counts: map[string]int{"malicious": 1, "suspicious": 0, "benign": 0, "unknown": 1},
			Items: []models.ThreatVerdict{
				{Value: "evil.example.com", Type: "domain-name", Verdict: "malicious", Score: 85, Action: "block", KnownSources: []string{"urlhaus"},
					Evidence: []models.ThreatEvidence{
						{Source: "urlhaus", Kind: "malicious", Weight: 85, Text: "Active <b>indicator</b> | serving malware", Ref: "javascript:alert(1)"},
						{Source: "virustotal", Kind: "suspicious", Weight: 40, Text: "3 of 70 engines", Ref: "https://www.virustotal.com/gui/domain/evil.example.com"},
					},
					Related: []string{"malware Emotet"}},
				{Value: "www.example.com", Type: "domain-name", Verdict: "unknown", Action: "monitor"},
			},
			Rejected: []models.ThreatRejected{{Value: "10.0.0.1", Reason: "non-public address"}},
		},
	}
}

func TestThreatIntelInHTMLReport(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderHTMLToWriter(threatReport(), &buf); err != nil {
		t.Fatal(err)
	}
	h := buf.String()
	for _, want := range []string{"Threat Intel (ThreatLens)", "evil.example.com", "MALICIOUS", "linked to malware Emotet", "10.0.0.1 (non-public address)", "https://www.virustotal.com/gui/domain/evil.example.com"} {
		if !strings.Contains(h, want) {
			t.Errorf("HTML report lacks %q", want)
		}
	}
	if strings.Contains(h, "<b>indicator</b>") || strings.Contains(h, `href="javascript:`) {
		t.Error("evidence from ThreatLens must be escaped and unsafe links neutralised")
	}
}

func TestThreatIntelInMarkdownReport(t *testing.T) {
	md := RenderMarkdown(threatReport())
	if !strings.Contains(md, "## Threat Intel (ThreatLens)") || !strings.Contains(md, "| `evil.example.com` | MALICIOUS | 85 | block |") {
		t.Fatalf("markdown section missing:\n%s", md)
	}
	if strings.Contains(md, "indicator</b> | serving") {
		t.Error("a pipe in evidence text must not break the table")
	}
	// IP-target scans have no passive intel but still get the section.
	ip := threatReport()
	ip.Target = &models.Target{Value: "93.184.216.34", Type: models.TargetTypeIPv4}
	if !strings.Contains(RenderMarkdown(ip), "Threat Intel (ThreatLens)") {
		t.Error("section missing for an IP target")
	}
}
