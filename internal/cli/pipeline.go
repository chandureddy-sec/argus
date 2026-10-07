package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"reconx/internal/correlate"
	rdns "reconx/internal/dns"
	"reconx/internal/history"
	"reconx/internal/intel"
	"reconx/internal/normalize"
	"reconx/internal/orchestrator"
	"reconx/internal/providers"
	"reconx/pkg/models"
)

// gatherSubdomains runs the passive multi-provider subdomain enumeration for a
// target and returns the raw provider results, the normalized/deduplicated
// assets, and the flat list of hostnames to resolve. This is the single source
// of truth shared by `scan`, the interactive runner, and the `subdomains`
// command, so their enumeration logic can no longer drift apart. The raw
// results are kept per source so provenance and observation dates survive.
func gatherSubdomains(ctx context.Context, t *models.Target) (raw []models.RawResult, assets []models.Asset, hostnames []string, statuses []orchestrator.ProviderStatus) {
	engine := orchestrator.NewEngine(getSubdomainProviders(), 35*time.Second)
	raw, statuses, _ = engine.RunRaw(ctx, *t)

	assets = normalize.NormalizeAndDedup(raw, normalize.DefaultOptions(t.Value))

	hostnames = make([]string, 0, len(assets))
	for _, a := range assets {
		hostnames = append(hostnames, a.Asset)
	}
	return raw, assets, hostnames, statuses
}

// providerStatusLine renders a compact one-line summary of provider outcomes,
// e.g. "crtsh=42 hackertarget=18 anubis=ERR(timeout) ...".
func providerStatusLine(statuses []orchestrator.ProviderStatus) string {
	parts := make([]string, 0, len(statuses))
	for _, s := range statuses {
		if errors.Is(s.Err, providers.ErrSkipped) {
			parts = append(parts, fmt.Sprintf("%s=skipped", s.Name))
		} else if s.Err != nil {
			parts = append(parts, fmt.Sprintf("%s=ERR", s.Name))
		} else {
			parts = append(parts, fmt.Sprintf("%s=%d", s.Name, s.Results))
		}
	}
	return strings.Join(parts, "  ")
}

// gatherPassiveIntel builds the evidence-backed passive intelligence for a
// domain report (certificates, historical DNS, email & DNS posture, IP/ASN
// enrichment, classification, confidence), compares it with the target's
// earlier saved scans, and fills report.Intel and the legacy report.Correlation
// graph. It returns the graph and the unique IPs for terminal display.
// Everything comes from public sources and public resolvers.
func gatherPassiveIntel(ctx context.Context, report *models.ScanReport, statuses []orchestrator.ProviderStatus, rdap *intel.SourceTiming, progress func(string)) (*models.Graph, []string) {
	domain := report.Target.Value
	out := intel.Collect(ctx, rdns.NewResolver(nil, 5*time.Second), intel.Input{
		Domain:   domain,
		DNS:      report.DNS,
		Raw:      report.Subdomains,
		Assets:   report.Assets,
		Statuses: statuses,
		RDAP:     rdap,
		Progress: progress,
	})
	report.Intel = out.Intel
	report.Subdomains, report.Assets = out.Raw, out.Assets

	history.Apply(report, history.LoadTarget("reports", domain))
	intel.Finalize(report.Intel)

	graph := correlate.BuildGraph(domain, report.Assets, out.HostIP, out.IPMeta)
	report.Correlation = graph

	uniqueIPs := make([]string, 0, len(out.Intel.IPs))
	for _, ip := range out.Intel.IPs {
		uniqueIPs = append(uniqueIPs, ip.IP)
	}
	return graph, uniqueIPs
}
