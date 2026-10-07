package cli

import (
	"path/filepath"
	"testing"
	"time"
)

func TestReportPaths(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 30, 0, 0, time.UTC)

	j, h, m := reportPaths("", "", "", "", "example.com", now)
	if j != filepath.Join("reports", "recon_example.com_20261007_123000.json") || h != filepath.Join("reports", "recon_example.com_20261007_123000.html") || m != filepath.Join("reports", "recon_example.com_20261007_123000.md") {
		t.Errorf("default paths wrong: %s %s %s", j, h, m)
	}

	j, h, _ = reportPaths(filepath.Join("out", "run1"), "", "", "", "10.0.0.0/24", now)
	if j != filepath.Join("out", "run1", "recon_10.0.0.0_24_20261007_123000.json") || filepath.Dir(h) != filepath.Join("out", "run1") {
		t.Errorf("-o not honoured / target not sanitised: %s %s", j, h)
	}

	j, h, m = reportPaths("out", "custom.json", "", "x/report.md", "example.com", now)
	if j != "custom.json" || m != "x/report.md" || filepath.Dir(h) != "out" {
		t.Errorf("explicit paths should override -o for their format only: %s %s %s", j, h, m)
	}
}
