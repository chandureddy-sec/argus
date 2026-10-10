package report

import (
	"fmt"
	"html/template"
	"strings"

	"reconx/pkg/models"
)

// threatTemplate renders the ThreatLens verdicts (scans run with --threatlens).
const threatTemplate = `{{define "threat"}}{{with .ThreatIntel}}
  <h2 class="section-title">Threat Intel (ThreatLens)</h2>
  <div class="card" style="margin-bottom:16px">
    <p style="margin:0 0 8px">
      {{len .Items}} hosts and IPs checked against <code>{{.Server}}</code> on {{.CheckedAt.Format "2006-01-02 15:04 UTC"}} as {{.TLP}}:
      <strong>{{index .Counts "malicious"}}</strong> malicious · <strong>{{index .Counts "suspicious"}}</strong> suspicious · {{index .Counts "benign"}} benign · {{index .Counts "unknown"}} unknown.
      {{if .BudgetSpent}}{{.BudgetSpent}} metered provider calls.{{end}}
    </p>
    <p style="margin:0"><small>Verdicts are ThreatLens's assessment from its feeds and third-party reputation, each with its evidence. An own asset listed as malicious usually means compromise or abuse, or a shared IP: verify before acting.</small></p>
    {{if .Error}}<p style="margin:8px 0 0;color:var(--orange)">ThreatLens {{if eq .Status "error"}}could not be used{{else}}stopped part-way{{end}}: {{.Error}}</p>{{end}}
  </div>
  {{if .Items}}
  <table>
    <thead><tr><th>Asset</th><th>Verdict</th><th>Score</th><th>Action</th><th>Evidence</th><th>Known to</th></tr></thead>
    <tbody>
      {{range .Items}}
      <tr>
        <td><strong>{{.Value}}</strong><br><small>{{.Type}}</small></td>
        <td><span class="badge" style="{{verdictStyle .Verdict}}">{{upper .Verdict}}</span>{{if .Partial}}<br><small title="{{join .Skipped "; "}}">partial</small>{{end}}</td>
        <td>{{.Score}}</td>
        <td>{{.Action}}</td>
        <td>{{range .Evidence}}{{if ne .Kind "info"}}<div><small><strong>{{.Kind}} {{.Weight}}</strong> · {{.Source}}: {{.Text}}{{if .Ref}} <a href="{{.Ref}}" target="_blank" rel="noopener noreferrer">↗</a>{{end}}</small></div>{{end}}{{end}}{{range .Related}}<div><small>linked to {{.}}</small></div>{{end}}</td>
        <td>{{if .KnownSources}}{{join .KnownSources ", "}}{{else}}—{{end}}</td>
      </tr>
      {{end}}
    </tbody>
  </table>
  {{end}}
  {{if .Rejected}}<p><small>Not checked: {{range $i, $r := .Rejected}}{{if $i}} · {{end}}{{$r.Value}} ({{$r.Reason}}){{end}}</small></p>{{end}}
{{end}}{{end}}`

// verdictStyle colours a ThreatLens verdict badge.
func verdictStyle(v string) template.CSS {
	switch v {
	case "malicious":
		return template.CSS("background:rgba(248,113,113,0.12);color:var(--red);border:1px solid rgba(248,113,113,0.4);")
	case "suspicious":
		return template.CSS("background:rgba(251,146,60,0.12);color:var(--orange);border:1px solid rgba(251,146,60,0.4);")
	case "benign":
		return template.CSS("background:rgba(215,255,224,0.10);color:var(--accent);border:1px solid rgba(215,255,224,0.3);")
	default:
		return template.CSS("background:#0b0f1a;color:var(--text);border:1px solid var(--border);")
	}
}

// writeThreatMarkdown renders the ThreatLens verdicts as Markdown.
func writeThreatMarkdown(sb *strings.Builder, ti *models.ThreatIntel) {
	cell := func(s string) string { return strings.ReplaceAll(strings.ReplaceAll(s, "|", "/"), "\n", " ") }
	sb.WriteString("## Threat Intel (ThreatLens)\n\n")
	fmt.Fprintf(sb, "%d hosts and IPs checked against `%s` on %s as %s: **%d malicious**, **%d suspicious**, %d benign, %d unknown.\n\n",
		len(ti.Items), ti.Server, ti.CheckedAt.Format("2006-01-02 15:04 UTC"), ti.TLP,
		ti.Counts["malicious"], ti.Counts["suspicious"], ti.Counts["benign"], ti.Counts["unknown"])
	if ti.Error != "" {
		fmt.Fprintf(sb, "> ThreatLens problem: %s\n\n", cell(ti.Error))
	}
	if len(ti.Items) == 0 {
		return
	}
	sb.WriteString("| Asset | Verdict | Score | Action | Strongest evidence | Known to |\n")
	sb.WriteString("| :--- | :--- | ---: | :--- | :--- | :--- |\n")
	for _, v := range ti.Items {
		ev := "—"
		for _, e := range v.Evidence {
			if e.Kind != "info" {
				ev = fmt.Sprintf("%s %d · %s: %s", e.Kind, e.Weight, e.Source, e.Text)
				break
			}
		}
		known := "—"
		if len(v.KnownSources) > 0 {
			known = strings.Join(v.KnownSources, ", ")
		}
		fmt.Fprintf(sb, "| `%s` | %s | %d | %s | %s | %s |\n", v.Value, strings.ToUpper(v.Verdict), v.Score, v.Action, cell(ev), cell(known))
	}
	sb.WriteString("\n")
}
