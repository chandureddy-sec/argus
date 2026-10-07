package cli

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"reconx/internal/orchestrator"
	"reconx/internal/providers"
	"reconx/internal/ui"
	"reconx/pkg/models"
)

// printExposure shows the Shodan InternetDB data attached to each IP.
func printExposure(pi *models.PassiveIntel) {
	if pi == nil || pi.Aggregates.ExposedIPs == 0 {
		return
	}
	ag := pi.Aggregates
	fmt.Printf("\n[+] Shodan InternetDB: %d of %d IPs indexed · %d open ports · %d distinct CVE IDs, %d in CISA KEV (unverified, from Shodan's last crawl)\n",
		ag.ExposedIPs, ag.UniqueIPs, ag.OpenPorts, ag.ReportedCVEs, ag.KEVCVEs)
	headers := []string{"IP", "Hostnames", "Open ports", "Tags", "Reported CVEs (unverified)"}
	var rows [][]string
	for _, ip := range pi.IPs {
		e := ip.Exposure
		if e == nil {
			continue
		}
		ports := make([]string, len(e.Ports))
		for i, p := range e.Ports {
			ports[i] = strconv.Itoa(p)
		}
		rows = append(rows, []string{ip.IP, clip(strings.Join(ip.Hostnames, ", "), 32), clip(strings.Join(ports, ","), 30),
			dashIfEmpty(strings.Join(e.Tags, ",")), cveSummary(e.Vulns)})
	}
	ui.PrintTable(headers, rows)
}

// printSkipped gives each deliberately skipped provider a one-line notice
// (e.g. an optional API key that is not configured).
func printSkipped(statuses []orchestrator.ProviderStatus) {
	for _, s := range statuses {
		if errors.Is(s.Err, providers.ErrSkipped) {
			fmt.Printf("[i] %s %s\n", s.Name, s.Err)
		}
	}
}

// printRoutingConflicts warns about IPs where RIPEstat and Team Cymru disagree.
func printRoutingConflicts(pi *models.PassiveIntel) {
	if pi == nil || pi.Aggregates.RoutingConflicts == 0 {
		return
	}
	fmt.Printf("\n[!] Routing cross-check: RIPEstat and Team Cymru disagree on %d IP(s):\n", pi.Aggregates.RoutingConflicts)
	for _, ip := range pi.IPs {
		if rc := ip.Routing; rc != nil && rc.Agreement == "disagree" {
			fmt.Printf("    %-16s %s\n", ip.IP, strings.Join(rc.Conflicts, "; "))
		}
	}
}

// cveSummary shows the count, how many are KEV-listed, and the top CVE
// (lists are already ordered KEV first, then by EPSS).
func cveSummary(v []models.CVERef) string {
	if len(v) == 0 {
		return "-"
	}
	kev := 0
	for _, c := range v {
		if c.KEV {
			kev++
		}
	}
	s := fmt.Sprintf("%d", len(v))
	if kev > 0 {
		s += fmt.Sprintf(" (%d KEV)", kev)
	}
	top := v[0].ID
	if v[0].KEV {
		top += " KEV"
	}
	if v[0].Enriched {
		top += fmt.Sprintf(" EPSS %.2f", v[0].EPSS)
	}
	return s + " · top: " + top
}

func clip(s string, n int) string {
	if s == "" {
		return "-"
	}
	if len(s) > n {
		return s[:n-3] + "..."
	}
	return s
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
