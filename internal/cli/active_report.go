package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	reporter "reconx/internal/report"
	"reconx/pkg/models"
)

// saveActiveReportBundle persists an active-recon ScanReport to the reports/
// directory in three formats sharing one timestamped basename: JSON (raw),
// HTML (styled), and Markdown (engagement notes). prefix is a short tag such as
// "probe" or "webmap". It returns the written paths; a per-format failure is
// collected but does not stop the others.
func saveActiveReportBundle(prefix string, scan *models.ScanReport) ([]string, error) {
	if err := os.MkdirAll("reports", 0755); err != nil {
		return nil, err
	}

	host := sanitizeForFilename(scan.Target.Value)
	ts := scan.Timestamp.Format("20060102_150405")
	base := filepath.Join("reports", fmt.Sprintf("%s_%s_%s", prefix, host, ts))

	var paths []string
	var errs []string

	jsonPath := base + ".json"
	if data, err := json.MarshalIndent(scan, "", "  "); err != nil {
		errs = append(errs, "json: "+err.Error())
	} else if err := os.WriteFile(jsonPath, data, 0644); err != nil {
		errs = append(errs, "json: "+err.Error())
	} else {
		paths = append(paths, jsonPath)
	}

	htmlPath := base + ".html"
	if err := reporter.GenerateHTML(scan, htmlPath); err != nil {
		errs = append(errs, "html: "+err.Error())
	} else {
		paths = append(paths, htmlPath)
	}

	mdPath := base + ".md"
	if err := reporter.GenerateMarkdown(scan, mdPath); err != nil {
		errs = append(errs, "md: "+err.Error())
	} else {
		paths = append(paths, mdPath)
	}

	if len(errs) > 0 {
		return paths, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return paths, nil
}

// sanitizeForFilename reduces a host to characters safe for a filename.
func sanitizeForFilename(host string) string {
	replacer := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "*", "_", "?", "_",
		"\"", "_", "<", "_", ">", "_", "|", "_", " ", "_")
	return replacer.Replace(host)
}

// mergeAPIEndpoints appends add to base, skipping endpoints already present by
// (method, URL). Existing entries win, preserving their source attribution.
func mergeAPIEndpoints(base, add []models.APIEndpoint) []models.APIEndpoint {
	seen := make(map[string]bool, len(base))
	for _, e := range base {
		seen[e.Method+" "+e.URL] = true
	}
	for _, e := range add {
		key := e.Method + " " + e.URL
		if seen[key] {
			continue
		}
		seen[key] = true
		base = append(base, e)
	}
	return base
}
