package report

import (
	"fmt"
	"strings"

	"reconx/pkg/models"
)

// writeIntelMarkdown renders the passive-intelligence sections of the
// Markdown report.
func writeIntelMarkdown(sb *strings.Builder, rep *models.ScanReport) {
	pi := rep.Intel
	ag := pi.Aggregates
	fmt.Fprintf(sb, "## Attack Surface\n\n")
	fmt.Fprintf(sb, "%d subdomains · %d resolving · %d unique IPs (%d IPv4 / %d IPv6) · %d ASNs · %d countries · %d certificates · %d high-interest hosts\n\n",
		ag.Subdomains, ag.Resolving, ag.UniqueIPs, ag.IPv4, ag.IPv6, ag.ASNs, ag.Countries, ag.Certificates, ag.HighInterest)
	if len(ag.ByCloud) > 0 {
		parts := make([]string, 0, len(ag.ByCloud))
		for _, c := range ag.ByCloud {
			parts = append(parts, fmt.Sprintf("%s (%d)", c.Name, c.Count))
		}
		fmt.Fprintf(sb, "- **Cloud / hosting / CDN (inferred):** %s\n", strings.Join(parts, ", "))
	}
	if len(ag.ByASN) > 0 {
		parts := make([]string, 0, len(ag.ByASN))
		for _, a := range ag.ByASN {
			parts = append(parts, strings.TrimSpace(a.ASN+" "+a.Name))
		}
		fmt.Fprintf(sb, "- **ASNs:** %s\n", strings.Join(parts, ", "))
	}
	sb.WriteString("\n")

	if ch := pi.Changes; ch != nil {
		s := ch.Summary
		fmt.Fprintf(sb, "## Changes Since Previous Scan (%s)\n\n", ch.PreviousScan.Format("2006-01-02"))
		fmt.Fprintf(sb, "+%d / -%d subdomains · %d hosts changed · +%d / -%d IPs · %d apex DNS changes · +%d certificates · %d provider changes\n\n",
			s.SubdomainsAdded, s.SubdomainsRemoved, s.HostsChanged, s.IPsAdded, s.IPsRemoved, s.DNSChanges, s.CertsAdded, s.ProviderChanges)
		for i, e := range ch.Events {
			if i == 50 {
				fmt.Fprintf(sb, "- … %d more (see JSON)\n", len(ch.Events)-50)
				break
			}
			fmt.Fprintf(sb, "- **%s** %s `%s`%s\n", e.Action, e.Category, e.Key, arrow(e.Old, e.New))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("## Subdomains\n\n")
	sb.WriteString("_DNS, IPs and sources are observed; ASN/org are enriched; cloud, role and interest are inferred and require verification._\n\n")
	sb.WriteString("| Hostname | Lifecycle | DNS | Confidence | Sources | IPs | Likely role | Cloud / CDN | Interest | Archived page (urlscan) |\n")
	sb.WriteString("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")
	for _, h := range pi.Hosts {
		fmt.Fprintf(sb, "| `%s` | %s | %s | %d (%s) | %s | %s | %s | %s | %s | %s |\n",
			h.Hostname, h.Lifecycle, h.DNSStatus, h.Confidence, h.ConfidenceLevel, strings.Join(h.Sources, ", "),
			dash(strings.Join(h.IPs, ", ")), h.Role, dash(strings.TrimSpace(h.CDN+" "+h.Cloud)), h.Interest, webCell(h.Web))
	}
	sb.WriteString("\n")

	if len(pi.Dangling) > 0 {
		sb.WriteString("## Potential Dangling DNS (requires verification)\n\n")
		for _, d := range pi.Dangling {
			fmt.Fprintf(sb, "- `%s` → `%s` — %s\n", d.Hostname, d.CNAME, d.Reason)
		}
		sb.WriteString("\n")
	}

	writeExposureMarkdown(sb, pi)
	writeRoutingMarkdown(sb, pi)
	writeCodeRefsMarkdown(sb, pi)

	if es := pi.Email; es != nil {
		fmt.Fprintf(sb, "## Email Security — %d/%d\n\n", es.Score, es.MaxScore)
		sb.WriteString("| Control | Points | Assessment |\n| :--- | :--- | :--- |\n")
		for _, it := range es.ScoreBreakdown {
			fmt.Fprintf(sb, "| %s | %d/%d | %s |\n", it.Control, it.Points, it.Max, it.Reason)
		}
		sb.WriteString("\n")
		if es.SPF.Present {
			fmt.Fprintf(sb, "- **SPF:** `%s` — %s; %d/10 DNS lookups\n", es.SPF.Raw, es.SPF.Policy, es.SPF.LookupCount)
		}
		if es.DMARC.Present {
			fmt.Fprintf(sb, "- **DMARC:** `%s` — %s\n", es.DMARC.Raw, es.DMARC.Posture)
		}
		for _, k := range es.DKIM.Found {
			fmt.Fprintf(sb, "- **DKIM:** `%s._domainkey` %s %d-bit %s\n", k.Selector, k.KeyType, k.KeyBits, k.Service)
		}
		if len(es.MailProviders) > 0 {
			fmt.Fprintf(sb, "- **Mail providers (inferred):** %s\n", strings.Join(es.MailProviders, ", "))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("## DNS Security\n\n")
	if pi.DNSSEC != nil {
		fmt.Fprintf(sb, "- **DNSSEC:** %s\n", pi.DNSSEC.Status)
	}
	if pi.CAA != nil {
		fmt.Fprintf(sb, "- **CAA:** %s %s\n", pi.CAA.Posture, strings.Join(pi.CAA.Issue, ", "))
	}
	cs := pi.CertSummary
	fmt.Fprintf(sb, "- **Certificates:** %d total · %d valid · %d expire <7d · %d expire 7–30d · %d expired · %d wildcard\n\n",
		cs.Total, cs.Valid, cs.Lt7, cs.Lt14+cs.Lt30, cs.Expired, cs.Wildcard)

	sb.WriteString("## Sources\n\n| Source | Status | Duration | Results | Reliability | Note |\n| :--- | :--- | :--- | :--- | :--- | :--- |\n")
	for _, s := range pi.Sources {
		fmt.Fprintf(sb, "| %s | %s | %.1fs | %d | %s | %s |\n", s.Name, s.Status, float64(s.DurationMs)/1000, s.Results, s.Reliability, dash(s.Error))
	}
	sb.WriteString("\n---\n\n")
}

func arrow(old, new string) string {
	switch {
	case old != "" && new != "":
		return fmt.Sprintf(": %s → %s", old, new)
	case new != "":
		return ": " + new
	case old != "":
		return ": was " + old
	}
	return ""
}

func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

// writeExposureMarkdown lists Shodan InternetDB data per IP.
func writeExposureMarkdown(sb *strings.Builder, pi *models.PassiveIntel) {
	ag := pi.Aggregates
	if ag.ExposedIPs == 0 {
		return
	}
	sb.WriteString("## Exposure — Shodan InternetDB\n\n")
	fmt.Fprintf(sb, "_%d of %d IPs indexed · %d open ports · %d distinct CVE IDs, %d in CISA KEV (ordered KEV first, then EPSS). Shodan's last crawl, not a live check; CVE IDs are version-based, unverified indicators._\n\n",
		ag.ExposedIPs, ag.UniqueIPs, ag.OpenPorts, ag.ReportedCVEs, ag.KEVCVEs)
	sb.WriteString("| IP | Hostnames | Open ports | CPEs | Tags | Reported CVEs |\n| :--- | :--- | :--- | :--- | :--- | :--- |\n")
	for _, ip := range pi.IPs {
		e := ip.Exposure
		if e == nil {
			continue
		}
		fmt.Fprintf(sb, "| `%s` | %s | %s | %s | %s | %s |\n", ip.IP, dash(strings.Join(ip.Hostnames, ", ")),
			dash(joinPorts(e.Ports)), dash(strings.Join(e.CPEs, ", ")), dash(strings.Join(e.Tags, ", ")), dash(cveList(e.Vulns, 10)))
	}
	sb.WriteString("\n")
}

// webCell summarises a urlscan capture for a Markdown table cell.
func webCell(w *models.WebCapture) string {
	if w == nil {
		return "-"
	}
	var parts []string
	for _, s := range []string{w.Title, w.Server, w.HTTPStatus, strings.Join(w.Technologies, ", ")} {
		if s != "" {
			parts = append(parts, strings.ReplaceAll(s, "|", "/"))
		}
	}
	links := "[scan](" + w.ScanURL + ")"
	if w.Screenshot != "" {
		links += " [screenshot](" + w.Screenshot + ")"
	}
	return strings.TrimSpace(strings.Join(parts, " · ") + " " + links)
}

// writeRoutingMarkdown summarises the RIPEstat / Team Cymru cross-check and
// lists every disagreement with both values.
func writeRoutingMarkdown(sb *strings.Builder, pi *models.PassiveIntel) {
	checked, agree := 0, 0
	for _, ip := range pi.IPs {
		if ip.Routing != nil {
			checked++
			if ip.Routing.Agreement == "agree" {
				agree++
			}
		}
	}
	if checked == 0 {
		return
	}
	sb.WriteString("## Routing Cross-check — RIPEstat vs Team Cymru\n\n")
	fmt.Fprintf(sb, "_%d IPs checked · %d agree · %d disagree. Both sources are BGP-derived; a disagreement is shown with both values rather than resolved._\n\n",
		checked, agree, pi.Aggregates.RoutingConflicts)
	if pi.Aggregates.RoutingConflicts == 0 {
		return
	}
	sb.WriteString("| IP | Conflicts | RIPEstat holder | Upstreams |\n| :--- | :--- | :--- | :--- |\n")
	for _, ip := range pi.IPs {
		if rc := ip.Routing; rc != nil && rc.Agreement == "disagree" {
			fmt.Fprintf(sb, "| `%s` | %s | %s | %s |\n", ip.IP, strings.Join(rc.Conflicts, "; "), dash(rc.Holder), dash(strings.Join(rc.Upstreams, ", ")))
		}
	}
	sb.WriteString("\n")
}

// writeCodeRefsMarkdown lists hosts found in public GitHub code with links.
func writeCodeRefsMarkdown(sb *strings.Builder, pi *models.PassiveIntel) {
	var rows []string
	for _, h := range pi.Hosts {
		if len(h.CodeRefs) == 0 {
			continue
		}
		links := make([]string, len(h.CodeRefs))
		for i, u := range h.CodeRefs {
			links[i] = fmt.Sprintf("[%s](%s)", strings.TrimPrefix(u, "https://github.com/"), u)
		}
		rows = append(rows, fmt.Sprintf("- `%s` — %s\n", h.Hostname, strings.Join(links, " · ")))
	}
	if len(rows) == 0 {
		return
	}
	sb.WriteString("## Hostnames Mentioned in Public Code (GitHub)\n\n")
	sb.WriteString("_A mention in code is weak evidence: it may be stale, an example, or a typo._\n\n")
	for _, r := range rows {
		sb.WriteString(r)
	}
	sb.WriteString("\n")
}
