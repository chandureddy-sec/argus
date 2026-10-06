package cli

import (
	"context"
	"sort"
	"strings"
	"time"

	"reconx/internal/modules/apicapture"
	"reconx/internal/modules/crawler"
	"reconx/internal/modules/headers"
	"reconx/internal/modules/httprobe"
	"reconx/internal/modules/jsanalysis"
	nmapmod "reconx/internal/modules/nmap"
	"reconx/internal/modules/portscan"
	"reconx/internal/modules/techdetect"
	tlsinspect "reconx/internal/modules/tls"
	"reconx/pkg/models"
)

// runActiveReconGather performs the direct-to-target probe modules (TLS, HTTP,
// tech fingerprint, security-header and cookie analysis) and returns a
// populated ActiveReconResult. It is display-free so it can feed `scan --active`
// and the reports. Individual module failures degrade gracefully to nil fields.
func runActiveReconGather(ctx context.Context, host string) *models.ActiveReconResult {
	ar := &models.ActiveReconResult{}

	if tlsInfo, err := tlsinspect.Inspect(ctx, host); err == nil {
		ar.TLS = tlsInfo
	}

	if probeResult, err := httprobe.Probe(ctx, host); err == nil {
		ar.HTTPProbe = probeResult
		ar.TechStack = techdetect.Detect(probeResult)

		headerFindings, findings := headers.AnalyzeHeaders(probeResult.Headers)
		findings = append(findings, headers.AnalyzeCookies(probeResult.Cookies)...)
		ar.HeaderChecks = headerFindings
		ar.Findings = findings
	}

	return ar
}

// runPortScanGather scans the common TCP ports on host and returns only the
// open ones, sorted by port number. Display-free, for `scan --active --ports`.
func runPortScanGather(ctx context.Context, host string) []models.PortResult {
	results, err := portscan.ScanPorts(ctx, host, portscan.CommonPorts, 2*time.Second)
	if err != nil {
		return nil
	}
	open := make([]models.PortResult, 0, len(results))
	for _, r := range results {
		if r.State == "open" {
			open = append(open, r)
		}
	}
	sort.Slice(open, func(i, j int) bool { return open[i].Port < open[j].Port })
	return open
}

// runWebMapGather performs the web-mapping modules (well-known files, BFS crawl,
// JS analysis, and optional headless-browser API capture) and returns a
// populated WebMapResult. Display-free, for `scan --active` and the reports.
func runWebMapGather(ctx context.Context, host string, useBrowser bool, maxDepth, maxPages int) *models.WebMapResult {
	rootURL := "https://" + host

	wk := crawler.FetchWellKnown(ctx, rootURL)
	wm := &models.WebMapResult{
		RobotsTxt:   wk.RobotsTxt,
		SitemapURLs: wk.SitemapURLs,
		SecurityTxt: wk.SecurityTxt,
	}

	opts := crawler.Options{
		MaxDepth:   maxDepth,
		MaxPages:   maxPages,
		Timeout:    15 * time.Second,
		UserAgent:  "ReconX/2.0 (security assessment; authorized)",
		SameOrigin: true,
	}
	if cr, err := crawler.Crawl(ctx, rootURL, opts); err == nil && cr != nil {
		wm.CrawledPages = cr.Pages
		wm.Forms = cr.Forms
		wm.APIs = cr.APIs
		wm.TotalPages = len(cr.Pages)

		if len(cr.ScriptURLs) > 0 {
			wm.JSFindings = jsanalysis.AnalyzeScripts(ctx, cr.ScriptURLs, host)
		}

		if useBrowser {
			if captured, _ := apicapture.Capture(ctx, rootURL, apicapture.DefaultOptions()); len(captured) > 0 {
				wm.APIs = mergeAPIEndpoints(wm.APIs, captured)
			}
		}
	}

	return wm
}

// runNmapGather runs an nmap scan for the active pipeline, translating
// ScanOptions into nmap module options. Display-free; returns a result even
// when nmap is unavailable so the reason can be surfaced in the report.
func runNmapGather(ctx context.Context, host string, opts ScanOptions) *models.NmapResult {
	o := nmapmod.Options{
		Profile: strings.ToLower(opts.NmapProfile),
		Ports:   opts.NmapPorts,
	}
	if strings.TrimSpace(opts.NmapArgs) != "" {
		o.Profile = nmapmod.ProfileCustom
		o.Args = strings.Fields(opts.NmapArgs)
		if err := nmapmod.ValidateArgs(o.Args); err != nil {
			return &models.NmapResult{Available: false, Unavailable: err.Error()}
		}
	}
	res, err := nmapmod.Run(ctx, host, o)
	if err != nil {
		return &models.NmapResult{Available: false, Unavailable: err.Error()}
	}
	return res
}
