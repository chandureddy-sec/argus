package report

import (
	"fmt"
	"sort"
	"strings"

	"reconx/pkg/models"
)

// sevRank orders severities most-critical first for stable sorting.
func sevRank(sev string) int {
	switch strings.ToUpper(sev) {
	case models.SeverityCritical:
		return 0
	case models.SeverityHigh:
		return 1
	case models.SeverityMedium:
		return 2
	case models.SeverityLow:
		return 3
	default: // INFO / unknown
		return 4
	}
}

// sortFindings returns a copy of findings ordered most-severe first.
func sortFindings(findings []models.Finding) []models.Finding {
	out := make([]models.Finding, len(findings))
	copy(out, findings)
	sort.SliceStable(out, func(i, j int) bool {
		return sevRank(out[i].Severity) < sevRank(out[j].Severity)
	})
	return out
}

// writeActiveReconMarkdown renders the active-recon section (TLS, HTTP probe,
// tech stack, open ports, security headers, findings) into sb.
func writeActiveReconMarkdown(sb *strings.Builder, ar *models.ActiveReconResult) {
	sb.WriteString("## Active Recon (Direct-to-Target)\n\n")

	if t := ar.TLS; t != nil {
		sb.WriteString("### TLS / SSL Certificate\n\n")
		sb.WriteString("| Field | Value |\n| :--- | :--- |\n")
		sb.WriteString(fmt.Sprintf("| Subject | %s |\n", mdOrDash(t.Subject)))
		sb.WriteString(fmt.Sprintf("| Issuer | %s |\n", mdOrDash(t.Issuer)))
		sb.WriteString(fmt.Sprintf("| TLS Version | %s |\n", mdOrDash(t.TLSVersion)))
		sb.WriteString(fmt.Sprintf("| Cipher Suite | `%s` |\n", t.CipherSuite))
		expiry := fmt.Sprintf("%s (%d days)", t.NotAfter.Format("2006-01-02"), t.DaysUntilExpiry)
		if t.IsExpired {
			expiry = "**EXPIRED** " + t.NotAfter.Format("2006-01-02")
		}
		sb.WriteString(fmt.Sprintf("| Validity | %s |\n", expiry))
		sb.WriteString(fmt.Sprintf("| Self-Signed | %v |\n", t.IsSelfSigned))
		if len(t.SANs) > 0 {
			sb.WriteString(fmt.Sprintf("| SANs | %s |\n", strings.Join(t.SANs, ", ")))
		}
		sb.WriteString("\n")
	}

	if p := ar.HTTPProbe; p != nil {
		sb.WriteString("### HTTP Response\n\n")
		sb.WriteString("| Field | Value |\n| :--- | :--- |\n")
		sb.WriteString(fmt.Sprintf("| Final URL | %s |\n", mdOrDash(p.FinalURL)))
		sb.WriteString(fmt.Sprintf("| Status | %d |\n", p.StatusCode))
		if p.Title != "" {
			sb.WriteString(fmt.Sprintf("| Page Title | %s |\n", p.Title))
		}
		sb.WriteString(fmt.Sprintf("| Server | %s |\n", mdOrDash(p.Server)))
		sb.WriteString(fmt.Sprintf("| Response Time | %dms |\n", p.ResponseTime))
		if len(p.RedirectChain) > 0 {
			sb.WriteString(fmt.Sprintf("| Redirect Chain | %s |\n", strings.Join(p.RedirectChain, " → ")))
		}
		sb.WriteString("\n")
	}

	if ts := ar.TechStack; ts != nil {
		sb.WriteString("### Technology Stack\n\n")
		sb.WriteString("| Component | Detected |\n| :--- | :--- |\n")
		sb.WriteString(fmt.Sprintf("| Web Server | %s |\n", mdOrDash(ts.WebServer)))
		sb.WriteString(fmt.Sprintf("| Language | %s |\n", mdOrDash(ts.Language)))
		sb.WriteString(fmt.Sprintf("| Framework | %s |\n", mdOrDash(ts.Framework)))
		sb.WriteString(fmt.Sprintf("| CDN | %s |\n", mdOrDash(ts.CDN)))
		sb.WriteString(fmt.Sprintf("| WAF | %s |\n", mdOrDash(ts.WAF)))
		sb.WriteString(fmt.Sprintf("| CMS | %s |\n", mdOrDash(ts.CMS)))
		if len(ts.OtherTechs) > 0 {
			sb.WriteString(fmt.Sprintf("| Other | %s |\n", strings.Join(ts.OtherTechs, ", ")))
		}
		sb.WriteString("\n")
	}

	if len(ar.OpenPorts) > 0 {
		sb.WriteString("### Open Ports\n\n")
		sb.WriteString("| Port | Service | State | Banner |\n| :--- | :--- | :--- | :--- |\n")
		for _, p := range ar.OpenPorts {
			sb.WriteString(fmt.Sprintf("| %d | %s | %s | %s |\n", p.Port, mdOrDash(p.Service), p.State, mdOrDash(p.Banner)))
		}
		sb.WriteString("\n")
	}

	if ar.Nmap != nil {
		writeNmapMarkdown(sb, ar.Nmap)
	}

	if len(ar.HeaderChecks) > 0 {
		sb.WriteString("### Security Headers\n\n")
		sb.WriteString("| Header | Present | Severity | Note |\n| :--- | :--- | :--- | :--- |\n")
		for _, h := range ar.HeaderChecks {
			present := "✗"
			if h.Present {
				present = "✓"
			}
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", h.Header, present, h.Severity, h.Note))
		}
		sb.WriteString("\n")
	}

	writeFindingsMarkdown(sb, ar.Findings)
	sb.WriteString("---\n\n")
}

// writeWebMapMarkdown renders the web-mapping section into sb.
func writeWebMapMarkdown(sb *strings.Builder, wm *models.WebMapResult) {
	sb.WriteString("## Web Mapping\n\n")
	sb.WriteString(fmt.Sprintf("- **Pages crawled:** %d\n", wm.TotalPages))
	sb.WriteString(fmt.Sprintf("- **Forms:** %d | **API endpoints:** %d | **Scripts analyzed:** %d\n", len(wm.Forms), len(wm.APIs), len(wm.JSFindings)))
	sb.WriteString(fmt.Sprintf("- **robots.txt:** %s | **sitemap URLs:** %d | **security.txt:** %s\n\n",
		yesNo(wm.RobotsTxt != ""), len(wm.SitemapURLs), yesNo(wm.SecurityTxt != "")))

	if len(wm.Forms) > 0 {
		sb.WriteString("### Forms\n\n")
		sb.WriteString("| Page | Action | Method | Type | CSRF |\n| :--- | :--- | :--- | :--- | :--- |\n")
		for _, f := range wm.Forms {
			formType := "form"
			if f.IsLogin {
				formType = "**LOGIN**"
			} else if f.IsFileUpload {
				formType = "**FILE UPLOAD**"
			}
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %v |\n",
				mdOrDash(f.PageURL), mdOrDash(f.Action), f.Method, formType, f.HasCSRFToken))
		}
		sb.WriteString("\n")
	}

	if len(wm.APIs) > 0 {
		sb.WriteString("### API Endpoints\n\n")
		sb.WriteString("| Endpoint | Method | Source | Status |\n| :--- | :--- | :--- | :--- |\n")
		for _, a := range wm.APIs {
			status := "-"
			if a.StatusCode > 0 {
				status = fmt.Sprintf("%d", a.StatusCode)
			}
			sb.WriteString(fmt.Sprintf("| `%s` | %s | %s | %s |\n", a.URL, mdOrDash(a.Method), a.Source, status))
		}
		sb.WriteString("\n")
	}

	// Surface JS findings that carry secrets or reachable source maps.
	var jsNotable []models.JSFinding
	for _, j := range wm.JSFindings {
		if len(j.Secrets) > 0 || j.SourceMapReachable {
			jsNotable = append(jsNotable, j)
		}
	}
	if len(jsNotable) > 0 {
		sb.WriteString("### JavaScript Findings\n\n")
		sb.WriteString("| Script | 3rd-Party | Secrets | Source Map |\n| :--- | :--- | :--- | :--- |\n")
		for _, j := range jsNotable {
			secrets := "-"
			if len(j.Secrets) > 0 {
				secrets = strings.Join(j.Secrets, ", ")
			}
			smap := "-"
			if j.SourceMapReachable {
				smap = "**REACHABLE**"
			}
			sb.WriteString(fmt.Sprintf("| `%s` | %v | %s | %s |\n", j.ScriptURL, j.IsThirdParty, secrets, smap))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("---\n\n")
}

// writeFindingsMarkdown renders a severity-ordered findings table.
func writeFindingsMarkdown(sb *strings.Builder, findings []models.Finding) {
	if len(findings) == 0 {
		return
	}
	sb.WriteString("### Security Findings\n\n")
	sb.WriteString("| Severity | Category | Finding | Evidence |\n| :--- | :--- | :--- | :--- |\n")
	for _, f := range sortFindings(findings) {
		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n",
			f.Severity, f.Category, f.Title, mdOrDash(f.Evidence)))
	}
	sb.WriteString("\n")
}

func mdOrDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func yesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// writeNmapMarkdown renders the nmap section of the Markdown report.
func writeNmapMarkdown(sb *strings.Builder, nm *models.NmapResult) {
	sb.WriteString("### Nmap\n\n")
	if !nm.Available {
		fmt.Fprintf(sb, "nmap scan not available: %s\n\n", nm.Unavailable)
		return
	}
	priv := "unprivileged connect scan (SYN/OS detection need elevation)"
	if nm.Privileged {
		priv = "privileged (raw packets)"
	}
	fmt.Fprintf(sb, "nmap %s · %s profile · %s scan · %s · %.1fs\n\n", nm.Version, nm.Profile, mdOrDash(nm.ScanType), priv, nm.ElapsedSec)
	fmt.Fprintf(sb, "`%s`\n\n", nm.Command)

	if len(nm.Ports) > 0 {
		sb.WriteString("| Port | Proto | State | Service | Version / Product | CPE |\n| :--- | :--- | :--- | :--- | :--- | :--- |\n")
		for _, p := range nm.Ports {
			fmt.Fprintf(sb, "| %d | %s | %s | %s | %s | %s |\n",
				p.Port, p.Protocol, p.State, mdOrDash(p.Service), mdOrDash(p.VersionString()), mdOrDash(strings.Join(p.CPE, ", ")))
		}
		sb.WriteString("\n")
	}
	if len(nm.OSMatches) > 0 {
		sb.WriteString("**OS detection (best guesses):** ")
		parts := make([]string, 0, len(nm.OSMatches))
		for _, m := range nm.OSMatches {
			parts = append(parts, fmt.Sprintf("%s (%d%%)", m.Name, m.Accuracy))
		}
		sb.WriteString(strings.Join(parts, " · ") + "\n\n")
	}
	for _, p := range nm.Ports {
		for _, s := range p.Scripts {
			fmt.Fprintf(sb, "**%d/%s %s:**\n\n```\n%s\n```\n\n", p.Port, p.Protocol, s.ID, s.Output)
		}
	}
	for _, s := range nm.HostScripts {
		fmt.Fprintf(sb, "**host %s:**\n\n```\n%s\n```\n\n", s.ID, s.Output)
	}
}
