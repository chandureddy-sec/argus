package report

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"reconx/pkg/models"
)

func TestGenerateReports(t *testing.T) {
	tempDir := t.TempDir()

	report := &models.ScanReport{
		Target: &models.Target{
			Value: "example.com",
			Type:  models.TargetTypeDomain,
		},
		Timestamp: time.Now().UTC(),
		Assets: []models.Asset{
			{Asset: "api.example.com", Sources: []string{"crtsh"}, Confidence: 0.85},
		},
		Correlation: &models.Graph{
			TargetDomain: "example.com",
			TotalAssets:  1,
			LiveAssets:   1,
			Nodes: []models.CorrelatedAsset{
				{
					Hostname:      "api.example.com",
					IsAlive:       true,
					ResolvedIPs:   []string{"93.184.216.34"},
					CloudProvider: "Cloudflare (CDN/Proxy)",
					Confidence:    0.85,
				},
			},
		},
	}

	// 1. Test Markdown Report
	mdFile := filepath.Join(tempDir, "report.md")
	if err := GenerateMarkdown(report, mdFile); err != nil {
		t.Fatalf("GenerateMarkdown failed: %v", err)
	}

	mdBytes, err := os.ReadFile(mdFile)
	if err != nil || len(mdBytes) == 0 {
		t.Fatalf("failed to read generated markdown or it's empty: %v", err)
	}

	// 2. Test HTML Report
	htmlFile := filepath.Join(tempDir, "report.html")
	if err := GenerateHTML(report, htmlFile); err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}

	htmlBytes, err := os.ReadFile(htmlFile)
	if err != nil || len(htmlBytes) == 0 {
		t.Fatalf("failed to read generated HTML or it's empty: %v", err)
	}
}
