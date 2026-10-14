package report

import (
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"reconx/pkg/models"
)

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ReconX Report - {{.Target.Value}}</title>
<style>
  :root {
    --bg: #050505;
    --card-bg: #111827;
    --border: #1f2937;
    --text: #9ca3af;
    --text-bright: #f3f4f6;
    --accent: #D7FFE0;
    --accent-glow: rgba(215, 255, 224, 0.15);
    --green: #D7FFE0;
    --red: #f87171;
    --orange: #fb923c;
  }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background-color: var(--bg);
    color: var(--text);
    margin: 0;
    padding: 32px 24px;
    line-height: 1.6;
  }
  .container {
    max-width: 1200px;
    margin: 0 auto;
  }
  header {
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 24px 28px;
    margin-bottom: 28px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.6);
  }
  header .title {
    display: flex;
    align-items: center;
    gap: 16px;
  }
  header .mark {
    flex: none;
    display: block;
  }
  h1 {
    color: var(--accent);
    margin: 0 0 6px 0;
    font-size: 24px;
    font-weight: 700;
    letter-spacing: -0.5px;
  }
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 6px 14px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.5px;
    text-transform: uppercase;
  }
  .badge-live { 
    background: rgba(215, 255, 224, 0.12); 
    color: var(--accent); 
    border: 1px solid rgba(215, 255, 224, 0.4); 
  }
  .badge-off { 
    background: rgba(248, 113, 113, 0.12); 
    color: var(--red); 
    border: 1px solid rgba(248, 113, 113, 0.4); 
  }
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 16px;
    margin-bottom: 32px;
  }
  .card {
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px 24px;
    transition: transform 0.15s ease, border-color 0.15s ease;
  }
  .card:hover {
    border-color: rgba(215, 255, 224, 0.3);
    transform: translateY(-2px);
  }
  .card h3 {
    margin: 0 0 10px 0;
    font-size: 12px;
    text-transform: uppercase;
    color: var(--text);
    letter-spacing: 1px;
    font-weight: 600;
  }
  .card .metric {
    font-size: 32px;
    font-weight: 800;
    color: var(--text-bright);
    letter-spacing: -1px;
  }
  table {
    width: 100%;
    border-collapse: separate;
    border-spacing: 0;
    margin-bottom: 32px;
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 10px;
    overflow: hidden;
  }
  th, td {
    padding: 12px 18px;
    text-align: left;
    border-bottom: 1px solid var(--border);
    font-size: 13px;
  }
  th {
    background: #090d16;
    color: var(--accent);
    font-weight: 700;
    text-transform: uppercase;
    font-size: 11px;
    letter-spacing: 0.8px;
  }
  tr:last-child td {
    border-bottom: none;
  }
  tr:hover td {
    background: rgba(215, 255, 224, 0.03);
  }
  code {
    background: #050505;
    padding: 3px 8px;
    border-radius: 6px;
    border: 1px solid var(--border);
    color: var(--accent);
    font-size: 12px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  }
  .section-title {
    font-size: 16px;
    font-weight: 700;
    color: var(--text-bright);
    margin: 32px 0 14px 0;
    border-left: 3px solid var(--accent);
    padding-left: 12px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  @media print {
    :root { --bg:#fff; --card-bg:#fff; --border:#d1d5db; --text:#111827; --text-bright:#000; --accent:#065f46; }
    body { padding: 0; font-size: 11px; }
    table { page-break-inside: auto; } tr { page-break-inside: avoid; }
    .section-title { page-break-after: avoid; }
    code { color: #065f46; background: #f3f4f6; }
  }
  footer {
    text-align: center;
    color: #6b7280;
    font-size: 12px;
    margin-top: 50px;
    padding-top: 24px;
    border-top: 1px solid var(--border);
  }
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="title">
      <svg class="mark" viewBox="0 0 64 64" width="44" height="44" aria-hidden="true"><defs> <linearGradient id="rx-g" x1="8" y1="56" x2="56" y2="8" gradientUnits="userSpaceOnUse"> <stop offset="0" stop-color="#a7e9c6"/> <stop offset=".55" stop-color="#34d3b4"/> <stop offset="1" stop-color="#22d3ee"/> </linearGradient> </defs> <rect x="3" y="3" width="58" height="58" rx="17" fill="#0e0b1d"/> <rect x="3" y="3" width="58" height="58" rx="17" fill="none" stroke="url(#rx-g)" stroke-width="2.5"/> <path d="M17 36.5a10.5 10.5 0 0 1 10.5 10.5" fill="none" stroke="url(#rx-g)" stroke-width="4.5" stroke-linecap="round"/> <path d="M17 26a21 21 0 0 1 21 21" fill="none" stroke="url(#rx-g)" stroke-width="4.5" stroke-linecap="round" opacity=".85"/> <path d="M17 47L40.5 23.5" stroke="url(#rx-g)" stroke-width="4.5" stroke-linecap="round"/> <circle cx="17" cy="47" r="3.5" fill="#a7e9c6"/> <circle cx="48" cy="16" r="4" fill="#ff4fa3"/></svg>
      <div>
      <h1>ReconX Security Assessment Report</h1>
      <div>Target: <strong>{{.Target.Value}}</strong> ({{.Target.Type}}) | Generated: {{.Timestamp.Format "2006-01-02 15:04:05 UTC"}}</div>
      </div>
    </div>
    <div>
      {{if or .ActiveRecon .WebMap}}
        <span class="badge badge-off">PASSIVE + ACTIVE METADATA</span>
      {{else}}
        <span class="badge badge-live">100% PASSIVE OSINT</span>
      {{end}}
    </div>
  </header>

  <div class="grid">
    <div class="card">
      <h3>Cataloged Subdomains</h3>
      <div class="metric">{{len .Assets}}</div>
    </div>
    <div class="card">
      <h3>Resolving Hosts</h3>
      <div class="metric">{{if .Correlation}}{{.Correlation.LiveAssets}}{{else}}0{{end}}</div>
    </div>
    <div class="card">
      <h3>DNS Records</h3>
      <div class="metric">{{if .DNS}}{{len .DNS.Records}}{{else}}0{{end}}</div>
    </div>
    <div class="card">
      <h3>Registrar</h3>
      <div style="font-size: 16px; font-weight: 600; color: var(--text-bright); margin-top: 8px;">
        {{if .RDAP}}{{.RDAP.Registrar}}{{else}}Unavailable{{end}}
      </div>
    </div>
  </div>

  {{template "intel" .}}

  {{template "threat" .}}

  {{if and .Correlation (not .Intel)}}
  <h2 class="section-title">Attack Surface Correlation (Resolving Infrastructure & Cloud Providers)</h2>
  <table>
    <thead>
      <tr>
        <th>#</th>
        <th>Discovered Hostname</th>
        <th>Status</th>
        <th>Resolved IP(s)</th>
        <th>Cloud / Hosting Provider</th>
        <th>ASN & Organization</th>
      </tr>
    </thead>
    <tbody>
      {{range $i, $node := .Correlation.Nodes}}
      <tr>
        <td>{{add $i 1}}</td>
        <td><strong>{{$node.Hostname}}</strong></td>
        <td>
          {{if $node.IsAlive}}
            <span class="badge badge-live">RESOLVES</span>
          {{else}}
            <span class="badge badge-off">NO DNS</span>
          {{end}}
        </td>
        <td>{{$node.PrimaryIPString}}</td>
        <td>{{$node.CloudProvider}}</td>
        <td>{{$node.ASN}}</td>
      </tr>
      {{end}}
    </tbody>
  </table>
  {{end}}

  {{if .DNS}}
  <h2 class="section-title">DNS Records & Routing Configuration</h2>
  <table>
    <thead>
      <tr>
        <th>Type</th>
        <th>Name</th>
        <th>TTL</th>
        <th>Resolved Value</th>
      </tr>
    </thead>
    <tbody>
      {{range .DNS.Records}}
      <tr>
        <td><span style="font-weight:600; color:var(--accent);">{{.Type}}</span></td>
        <td>{{.Name}}</td>
        <td>{{.TTL}}s</td>
        <td><code>{{.Value}}</code></td>
      </tr>
      {{end}}
    </tbody>
  </table>

  {{if not .Intel}}
  <h2 class="section-title">Mail Security</h2>
  <table>
    <thead>
      <tr>
        <th>Protocol</th>
        <th>Configured Record</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>SPF</strong></td>
        <td><code>{{if .DNS.SecurityRecords.SPF}}{{.DNS.SecurityRecords.SPF}}{{else}}Missing / Not Configured{{end}}</code></td>
      </tr>
      <tr>
        <td><strong>DMARC</strong></td>
        <td><code>{{if .DNS.SecurityRecords.DMARC}}{{.DNS.SecurityRecords.DMARC}}{{else}}Missing / Not Configured{{end}}</code></td>
      </tr>
    </tbody>
  </table>
  {{end}}
  {{end}}

  {{if .RDAP}}
  <h2 class="section-title">Domain Registration (WHOIS / RDAP)</h2>
  <table>
    <thead>
      <tr><th>Field</th><th>Value</th></tr>
    </thead>
    <tbody>
      <tr><td><strong>Registrar</strong></td><td>{{.RDAP.Registrar}}</td></tr>
      <tr><td><strong>Registrant Org</strong></td><td>{{if .RDAP.Organization}}{{.RDAP.Organization}}{{else}}-{{end}}</td></tr>
      <tr><td><strong>Country</strong></td><td>{{if .RDAP.Country}}{{.RDAP.Country}}{{else}}-{{end}}</td></tr>
      <tr><td><strong>Created</strong></td><td>{{if not .RDAP.CreatedDate.IsZero}}{{.RDAP.CreatedDate.Format "2006-01-02"}}{{else}}-{{end}}</td></tr>
      <tr><td><strong>Expires</strong></td><td>{{if not .RDAP.ExpiryDate.IsZero}}{{.RDAP.ExpiryDate.Format "2006-01-02"}}{{else}}-{{end}}</td></tr>
      <tr><td><strong>Last Updated</strong></td><td>{{if not .RDAP.UpdatedDate.IsZero}}{{.RDAP.UpdatedDate.Format "2006-01-02"}}{{else}}-{{end}}</td></tr>
    </tbody>
  </table>
  {{end}}

  {{if .Assets}}
  {{if not .Correlation}}
  <h2 class="section-title">Discovered Subdomains</h2>
  <table>
    <thead>
      <tr><th>#</th><th>Subdomain</th><th>Sources</th><th>Confidence</th></tr>
    </thead>
    <tbody>
      {{range $i, $a := .Assets}}
      <tr>
        <td>{{add $i 1}}</td>
        <td><strong>{{$a.Asset}}</strong></td>
        <td>{{join $a.Sources ", "}}</td>
        <td>{{printf "%.2f" $a.Confidence}}</td>
      </tr>
      {{end}}
    </tbody>
  </table>
  {{end}}
  {{end}}

  {{if .ActiveRecon}}
  <h2 class="section-title">Active Recon (Direct-to-Target)</h2>
  {{with .ActiveRecon.TLS}}
  <h3 style="color:var(--text-bright);">TLS / SSL Certificate</h3>
  <table>
    <tbody>
      <tr><td><strong>Subject</strong></td><td>{{.Subject}}</td></tr>
      <tr><td><strong>Issuer</strong></td><td>{{.Issuer}}</td></tr>
      <tr><td><strong>TLS Version</strong></td><td>{{.TLSVersion}}</td></tr>
      <tr><td><strong>Cipher Suite</strong></td><td><code>{{.CipherSuite}}</code></td></tr>
      <tr><td><strong>Validity</strong></td><td>{{if .IsExpired}}<span class="badge badge-off">EXPIRED</span> {{end}}{{.NotAfter.Format "2006-01-02"}} ({{.DaysUntilExpiry}} days)</td></tr>
      <tr><td><strong>Self-Signed</strong></td><td>{{.IsSelfSigned}}</td></tr>
      {{if .SANs}}<tr><td><strong>SANs</strong></td><td>{{join .SANs ", "}}</td></tr>{{end}}
    </tbody>
  </table>
  {{end}}
  {{with .ActiveRecon.HTTPProbe}}
  <h3 style="color:var(--text-bright);">HTTP Response</h3>
  <table>
    <tbody>
      <tr><td><strong>Final URL</strong></td><td><code>{{.FinalURL}}</code></td></tr>
      <tr><td><strong>Status</strong></td><td>{{.StatusCode}}</td></tr>
      {{if .Title}}<tr><td><strong>Page Title</strong></td><td>{{.Title}}</td></tr>{{end}}
      <tr><td><strong>Server</strong></td><td>{{if .Server}}{{.Server}}{{else}}-{{end}}</td></tr>
      <tr><td><strong>Response Time</strong></td><td>{{.ResponseTime}}ms</td></tr>
      {{if .RedirectChain}}<tr><td><strong>Redirect Chain</strong></td><td>{{join .RedirectChain " → "}}</td></tr>{{end}}
    </tbody>
  </table>
  {{end}}
  {{with .ActiveRecon.TechStack}}
  <h3 style="color:var(--text-bright);">Technology Stack</h3>
  <table>
    <tbody>
      <tr><td><strong>Web Server</strong></td><td>{{if .WebServer}}{{.WebServer}}{{else}}-{{end}}</td></tr>
      <tr><td><strong>Language</strong></td><td>{{if .Language}}{{.Language}}{{else}}-{{end}}</td></tr>
      <tr><td><strong>Framework</strong></td><td>{{if .Framework}}{{.Framework}}{{else}}-{{end}}</td></tr>
      <tr><td><strong>CDN</strong></td><td>{{if .CDN}}{{.CDN}}{{else}}-{{end}}</td></tr>
      <tr><td><strong>WAF</strong></td><td>{{if .WAF}}{{.WAF}}{{else}}-{{end}}</td></tr>
      <tr><td><strong>CMS</strong></td><td>{{if .CMS}}{{.CMS}}{{else}}-{{end}}</td></tr>
      {{if .OtherTechs}}<tr><td><strong>Other</strong></td><td>{{join .OtherTechs ", "}}</td></tr>{{end}}
    </tbody>
  </table>
  {{end}}
  {{if .ActiveRecon.OpenPorts}}
  <h3 style="color:var(--text-bright);">Open Ports</h3>
  <table>
    <thead><tr><th>Port</th><th>Service</th><th>State</th><th>Banner</th></tr></thead>
    <tbody>
      {{range .ActiveRecon.OpenPorts}}
      <tr><td>{{.Port}}</td><td>{{.Service}}</td><td>{{.State}}</td><td><code>{{.Banner}}</code></td></tr>
      {{end}}
    </tbody>
  </table>
  {{end}}
  {{with .ActiveRecon.Nmap}}{{if .Available}}
  <h3 style="color:var(--text-bright);">Nmap — {{.Profile}} scan</h3>
  <p><small>nmap {{.Version}} · {{.ScanType}} scan · {{if .Privileged}}privileged (raw packets){{else}}unprivileged connect scan — SYN/OS detection need elevation{{end}} · {{printf "%.1f" .ElapsedSec}}s<br><code>{{.Command}}</code></small></p>
  <table>
    <thead><tr><th>Port</th><th>Proto</th><th>State</th><th>Service</th><th>Version / Product</th><th>CPE</th></tr></thead>
    <tbody>
      {{range .Ports}}<tr><td>{{.Port}}</td><td>{{.Protocol}}</td><td>{{.State}}</td><td>{{.Service}}</td><td>{{.VersionString}}</td><td><small>{{join .CPE ", "}}</small></td></tr>{{end}}
    </tbody>
  </table>
  {{if .OSMatches}}<p><strong>OS detection (best guesses):</strong> {{range $i, $m := .OSMatches}}{{if $i}} · {{end}}{{$m.Name}} ({{$m.Accuracy}}%){{end}}</p>{{end}}
  {{if .HostScripts}}<h4 style="color:var(--text-bright);">Host scripts</h4>{{range .HostScripts}}<p><code>{{.ID}}</code></p><pre style="white-space:pre-wrap;background:#0b0f1a;border:1px solid var(--border);border-radius:6px;padding:8px;font-size:12px;">{{.Output}}</pre>{{end}}{{end}}
  {{$hasScripts := false}}{{range .Ports}}{{if .Scripts}}{{$hasScripts = true}}{{end}}{{end}}
  {{if $hasScripts}}<h4 style="color:var(--text-bright);">Script output</h4>{{range $p := .Ports}}{{range $p.Scripts}}<p><code>{{$p.Port}}/{{$p.Protocol}}</code> — {{.ID}}</p><pre style="white-space:pre-wrap;background:#0b0f1a;border:1px solid var(--border);border-radius:6px;padding:8px;font-size:12px;">{{.Output}}</pre>{{end}}{{end}}{{end}}
  {{if .Warnings}}<p><small>nmap notices: {{join .Warnings " · "}}</small></p>{{end}}
  {{else}}
  <h3 style="color:var(--text-bright);">Nmap</h3>
  <p><small>nmap scan not available: {{.Unavailable}}</small></p>
  {{end}}{{end}}
  {{if .ActiveRecon.HeaderChecks}}
  <h3 style="color:var(--text-bright);">Security Headers</h3>
  <table>
    <thead><tr><th>Header</th><th>Present</th><th>Severity</th><th>Note</th></tr></thead>
    <tbody>
      {{range .ActiveRecon.HeaderChecks}}
      <tr><td><strong>{{.Header}}</strong></td><td>{{if .Present}}✓{{else}}✗{{end}}</td><td><span class="badge" style="{{sevStyle .Severity}}">{{.Severity}}</span></td><td>{{.Note}}</td></tr>
      {{end}}
    </tbody>
  </table>
  {{end}}
  {{if .ActiveRecon.Findings}}
  <h3 style="color:var(--text-bright);">Security Findings</h3>
  <table>
    <thead><tr><th>Severity</th><th>Category</th><th>Finding</th><th>Evidence</th></tr></thead>
    <tbody>
      {{range sortFindings .ActiveRecon.Findings}}
      <tr><td><span class="badge" style="{{sevStyle .Severity}}">{{.Severity}}</span></td><td>{{.Category}}</td><td>{{.Title}}</td><td>{{if .Evidence}}<code>{{.Evidence}}</code>{{else}}-{{end}}</td></tr>
      {{end}}
    </tbody>
  </table>
  {{end}}
  {{end}}

  {{if .WebMap}}
  <h2 class="section-title">Web Mapping</h2>
  <div class="grid">
    <div class="card"><h3>Pages Crawled</h3><div class="metric">{{.WebMap.TotalPages}}</div></div>
    <div class="card"><h3>Forms</h3><div class="metric">{{len .WebMap.Forms}}</div></div>
    <div class="card"><h3>API Endpoints</h3><div class="metric">{{len .WebMap.APIs}}</div></div>
    <div class="card"><h3>Scripts Analyzed</h3><div class="metric">{{len .WebMap.JSFindings}}</div></div>
  </div>
  {{if .WebMap.Forms}}
  <h3 style="color:var(--text-bright);">Forms</h3>
  <table>
    <thead><tr><th>Page</th><th>Action</th><th>Method</th><th>Type</th><th>CSRF</th></tr></thead>
    <tbody>
      {{range .WebMap.Forms}}
      <tr><td><code>{{.PageURL}}</code></td><td>{{.Action}}</td><td>{{.Method}}</td><td>{{if .IsLogin}}<span class="badge badge-off">LOGIN</span>{{else if .IsFileUpload}}<span class="badge badge-off">FILE UPLOAD</span>{{else}}form{{end}}</td><td>{{.HasCSRFToken}}</td></tr>
      {{end}}
    </tbody>
  </table>
  {{end}}
  {{if .WebMap.APIs}}
  <h3 style="color:var(--text-bright);">API Endpoints</h3>
  <table>
    <thead><tr><th>Endpoint</th><th>Method</th><th>Source</th><th>Status</th></tr></thead>
    <tbody>
      {{range .WebMap.APIs}}
      <tr><td><code>{{.URL}}</code></td><td>{{if .Method}}{{.Method}}{{else}}-{{end}}</td><td>{{.Source}}</td><td>{{if .StatusCode}}{{.StatusCode}}{{else}}-{{end}}</td></tr>
      {{end}}
    </tbody>
  </table>
  {{end}}
  {{end}}

  <footer>
    Generated by <strong>ReconX</strong> &bull; Authorized security assessments only.
  </footer>
</div>
</body>
</html>`

// GenerateHTML writes a standalone HTML report.
func GenerateHTML(report *models.ScanReport, destPath string) error {
	if destPath == "" {
		_ = os.MkdirAll("reports", 0755)
		destPath = filepath.Join("reports", fmt.Sprintf("report_%s_%s.html", report.Target.Value, report.Timestamp.Format("20060102_150405")))
	}

	tmpl, err := parseReportTemplate()
	if err != nil {
		return fmt.Errorf("failed to parse HTML template: %w", err)
	}

	f, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create HTML report file: %w", err)
	}
	defer f.Close()

	return tmpl.Execute(f, report)
}

// RenderHTMLToWriter renders the report HTML directly to any io.Writer.
func RenderHTMLToWriter(report *models.ScanReport, w io.Writer) error {
	tmpl, err := parseReportTemplate()
	if err != nil {
		return err
	}
	return tmpl.Execute(w, report)
}

// parseReportTemplate parses the main report template plus the passive
// intelligence sections it includes.
func parseReportTemplate() (*template.Template, error) {
	tmpl, err := template.New("report").Funcs(reportFuncMap()).Parse(htmlTemplate)
	if err != nil {
		return nil, err
	}
	if tmpl, err = tmpl.Parse(intelTemplate); err != nil {
		return nil, err
	}
	return tmpl.Parse(threatTemplate)
}

// reportFuncMap is the shared set of template helpers for the HTML report.
func reportFuncMap() template.FuncMap {
	return template.FuncMap{
		"add":          func(a, b int) int { return a + b },
		"join":         func(s []string, sep string) string { return strings.Join(s, sep) },
		"ports":        joinPorts,
		"cves":         cveList,
		"sortFindings": sortFindings,
		"sevStyle":     sevStyle,
		"verdictStyle": verdictStyle,
		"upper":        strings.ToUpper,
		"geomap":       geoMapSVG,
		"day":          day,
		"ms":           func(ms int64) string { return fmt.Sprintf("%.1fs", float64(ms)/1000) },
		"yesno": func(b bool) string {
			if b {
				return "✓"
			}
			return "✗"
		},
	}
}

// joinPorts renders a port list as "22, 80, 443".
func joinPorts(ports []int) string {
	out := make([]string, len(ports))
	for i, p := range ports {
		out[i] = strconv.Itoa(p)
	}
	return strings.Join(out, ", ")
}

// cveLabel renders one CVE with its triage context, e.g.
// "CVE-2021-44228 [KEV, ransomware] EPSS 1.00 CVSS 10.0".
func cveLabel(v models.CVERef) string {
	s := v.ID
	var flags []string
	if v.KEV {
		flags = append(flags, "KEV")
	}
	if v.Ransomware == "Known" {
		flags = append(flags, "ransomware")
	}
	if len(flags) > 0 {
		s += " [" + strings.Join(flags, ", ") + "]"
	}
	if v.Enriched {
		s += fmt.Sprintf(" EPSS %.2f", v.EPSS)
		if v.CVSS > 0 {
			s += fmt.Sprintf(" CVSS %.1f", v.CVSS)
		}
	}
	return s
}

// cveList renders up to max CVEs (already triage-ordered) and a "+N more" tail.
func cveList(vs []models.CVERef, max int) string {
	out := make([]string, 0, max)
	for i, v := range vs {
		if i == max {
			out = append(out, fmt.Sprintf("+%d more", len(vs)-max))
			break
		}
		out = append(out, cveLabel(v))
	}
	return strings.Join(out, "; ")
}

// sevStyle returns inline CSS coloring a severity badge by level.
func sevStyle(sev string) template.CSS {
	switch strings.ToUpper(sev) {
	case models.SeverityCritical, models.SeverityHigh:
		return template.CSS("background:rgba(248,113,113,0.12);color:var(--red);border:1px solid rgba(248,113,113,0.4);")
	case models.SeverityMedium:
		return template.CSS("background:rgba(251,146,60,0.12);color:var(--orange);border:1px solid rgba(251,146,60,0.4);")
	case models.SeverityLow:
		return template.CSS("background:rgba(215,255,224,0.10);color:var(--accent);border:1px solid rgba(215,255,224,0.3);")
	default:
		return template.CSS("background:#0b0f1a;color:var(--text);border:1px solid var(--border);")
	}
}
