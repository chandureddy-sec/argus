package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"reconx/internal/dns"
	"reconx/internal/intel"
	reporter "reconx/internal/report"
	"reconx/internal/storage"
	"reconx/internal/target"
	"reconx/internal/whois"
	"reconx/pkg/models"
)

// ScanOptions configures a programmatic scan run (used by the web server).
type ScanOptions struct {
	Target      string `json:"target"`
	Mode        string `json:"mode"` // "passive" | "active" | "both"
	Authorized  bool   `json:"authorized"`
	Ports       bool   `json:"ports"`
	Browser     bool   `json:"browser"`
	Nmap        bool   `json:"nmap"`         // run an nmap scan in the active phase
	NmapProfile string `json:"nmap_profile"` // quick | aggressive | full
	NmapPorts   string `json:"nmap_ports"`   // nmap -p spec
	NmapArgs    string `json:"nmap_args"`    // raw nmap flag passthrough (custom profile)
	MaxDepth    int    `json:"max_depth"`
	MaxPages    int    `json:"max_pages"`
	// Persist, when true, writes the JSON/HTML/MD report files and a drift-DB
	// entry. The web dashboard leaves this false and offers on-demand downloads
	// instead, so scans aren't written to disk unless the user asks.
	Persist bool `json:"-"`
}

// ProgressEvent is a single step update emitted during a scan.
type ProgressEvent struct {
	Step    string `json:"step"`
	Message string `json:"message"`
	Percent int    `json:"percent"`
	Level   string `json:"level"` // info | warn | done | error
}

// ScanResult bundles the finished report with the paths of the files written.
type ScanResult struct {
	Report *models.ScanReport `json:"report"`
	Files  []string           `json:"files"`
}

func (o ScanOptions) wantsPassive() bool { return o.Mode == "passive" || o.Mode == "both" }
func (o ScanOptions) wantsActive() bool  { return o.Mode == "active" || o.Mode == "both" }

// RunScanPipeline executes a scan without any terminal output, emitting
// progress through the optional callback and returning the populated report.
// It is the single engine shared by the `serve` web UI (and available to any
// other non-terminal caller). Active phases require opts.Authorized.
func RunScanPipeline(ctx context.Context, opts ScanOptions, progress func(ProgressEvent)) (*ScanResult, error) {
	emit := func(step, msg string, pct int, level string) {
		if progress != nil {
			progress(ProgressEvent{Step: step, Message: msg, Percent: pct, Level: level})
		}
	}

	parsed, err := target.Parse(opts.Target)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}

	if opts.wantsActive() && !opts.Authorized {
		return nil, fmt.Errorf("active recon requires authorization confirmation")
	}
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = 2
	}
	if opts.MaxPages <= 0 {
		opts.MaxPages = 25
	}

	report := &models.ScanReport{Target: parsed, Timestamp: time.Now().UTC()}
	start := time.Now()
	emit("start", "Starting scan of "+parsed.Value, 2, "info")

	isDomain := parsed.Type == models.TargetTypeDomain

	// ── Passive phase ──────────────────────────────────────────────────────────
	if opts.wantsPassive() && isDomain {
		emit("rdap", "WHOIS / RDAP registration lookup…", 8, "info")
		rdapStart := time.Now()
		rec, rdapErr := whois.NewClient(10*time.Second).Lookup(ctx, parsed.Value)
		rdapTiming := &intel.SourceTiming{Duration: time.Since(rdapStart), Err: rdapErr}
		if rdapErr == nil {
			report.RDAP = rec
			rdapTiming.Results = 1
		}

		emit("dns", "Resolving DNS records…", 14, "info")
		if res, err := dns.NewResolver(nil, 5*time.Second).Lookup(ctx, parsed.Value); err == nil {
			report.DNS = res
		}

		emit("subdomains", fmt.Sprintf("Passive subdomain discovery (%d public sources)…", len(getSubdomainProviders())), 20, "info")
		raw, assets, _, statuses := gatherSubdomains(ctx, parsed)
		report.Subdomains = raw
		report.Assets = assets
		emit("subdomains", fmt.Sprintf("%d subdomains found · %s", len(assets), providerStatusLine(statuses)), 45, "info")

		// Intel stages report their own progress; spread them over 48–68%.
		pct := 48
		gatherPassiveIntel(ctx, report, statuses, rdapTiming, func(msg string) {
			emit("intel", msg, pct, "info")
			if pct < 68 {
				pct += 4
			}
		})
		if ch := report.Intel.Changes; ch != nil {
			c := ch.Summary
			emit("changes", fmt.Sprintf("Since previous scan: +%d / -%d subdomains, %d hosts changed, +%d / -%d IPs, %d DNS changes",
				c.SubdomainsAdded, c.SubdomainsRemoved, c.HostsChanged, c.IPsAdded, c.IPsRemoved, c.DNSChanges), 69, "info")
		}
	}

	// ── Active phase ───────────────────────────────────────────────────────────
	if opts.wantsActive() && isDomain {
		emit("active", "Active recon: TLS, HTTP, headers, cookies…", 70, "info")
		report.ActiveRecon = runActiveReconGather(ctx, parsed.Value)

		if opts.Ports {
			emit("ports", "TCP port scan (common ports)…", 78, "info")
			report.ActiveRecon.OpenPorts = runPortScanGather(ctx, parsed.Value)
		}

		if opts.Nmap {
			emit("nmap", "nmap scan ("+firstNonEmptyStr(opts.NmapProfile, "quick")+" profile)…", 82, "info")
			nm := runNmapGather(ctx, parsed.Value, opts)
			report.ActiveRecon.Nmap = nm
			// nmap's richer open-port data supersedes the basic scan's.
			if nm != nil && nm.Available {
				if open := nm.OpenPortsLegacy(); len(open) > 0 {
					report.ActiveRecon.OpenPorts = open
				}
				msg := "nmap: " + firstNonEmptyStr(nm.Summary, "complete")
				if !nm.Privileged {
					msg += " (unprivileged connect scan; run elevated for SYN/OS detection)"
				}
				emit("nmap", msg, 84, "info")
			} else if nm != nil {
				emit("nmap", "nmap unavailable: "+nm.Unavailable, 84, "warn")
			}
		}

		emit("webmap", "Crawling & web mapping…", 85, "info")
		report.WebMap = runWebMapGather(ctx, parsed.Value, opts.Browser, opts.MaxDepth, opts.MaxPages)
	}

	// ── Persist (only on request; the web UI saves on demand instead) ────────────
	var files []string
	if opts.Persist {
		emit("store", "Saving report files and local database…", 94, "info")
		files = persistScan(ctx, report, time.Since(start))
	}

	emit("done", fmt.Sprintf("Scan complete in %s", time.Since(start).Round(time.Second)), 100, "done")
	return &ScanResult{Report: report, Files: files}, nil
}

// persistScan records a finished scan in the drift database and writes its
// JSON/HTML/MD report files, returning the paths written.
func persistScan(ctx context.Context, report *models.ScanReport, elapsed time.Duration) []string {
	if db, err := storage.Open(""); err == nil {
		_, _ = db.SaveScan(ctx, report.Target, report.Correlation, elapsed)
		db.Close()
	}
	return saveScanReportFiles(report)
}

// saveJSON writes v as indented JSON to path.
func saveJSON(path string, v interface{}) (string, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return "", err
	}
	return path, nil
}

// saveScanReportFiles writes the JSON/HTML/MD trio for a scan report to the
// reports/ directory and returns the paths written.
func saveScanReportFiles(report *models.ScanReport) []string {
	_ = os.MkdirAll("reports", 0755)
	base := filepath.Join("reports", fmt.Sprintf("recon_%s_%s",
		sanitizeForFilename(report.Target.Value), report.Timestamp.Format("20060102_150405")))

	var files []string
	jsonPath := base + ".json"
	if _, err := saveJSON(jsonPath, report); err == nil {
		files = append(files, jsonPath)
	}
	htmlPath := base + ".html"
	if err := reporter.GenerateHTML(report, htmlPath); err == nil {
		files = append(files, htmlPath)
	}
	mdPath := base + ".md"
	if err := reporter.GenerateMarkdown(report, mdPath); err == nil {
		files = append(files, mdPath)
	}
	return files
}
