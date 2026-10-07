package report

// intelTemplate renders the passive-intelligence sections of the HTML report:
// an executive summary followed by the technical evidence. It is defined as a
// named template and invoked from htmlTemplate when a report carries intel.
const intelTemplate = `{{define "intel"}}{{with .Intel}}
  <h2 class="section-title">Executive Summary</h2>
  <div class="card" style="margin-bottom:16px">
    <p style="margin:0 0 10px;color:var(--text-bright)">
      Passive-only assessment of <strong>{{$.Target.Value}}</strong> on {{$.Timestamp.Format "2006-01-02 15:04 UTC"}}.
      All data comes from public third-party sources and public DNS resolvers; no requests were sent to the target's own servers{{if or $.ActiveRecon $.WebMap}} by the passive scan (Active Metadata is reported separately below){{end}}.
    </p>
    <table>
      <tbody>
        <tr><td><strong>Attack surface</strong></td><td>{{.Aggregates.Subdomains}} subdomains · {{.Aggregates.Resolving}} resolving · {{.Aggregates.UniqueIPs}} unique IPs ({{.Aggregates.IPv4}} IPv4 / {{.Aggregates.IPv6}} IPv6) · {{.Aggregates.ASNs}} ASNs · {{.Aggregates.Countries}} countries</td></tr>
        {{with .Changes}}<tr><td><strong>Since previous scan</strong><br><small>{{.PreviousScan.Format "2006-01-02"}}</small></td><td>+{{.Summary.SubdomainsAdded}} / −{{.Summary.SubdomainsRemoved}} subdomains · {{.Summary.HostsChanged}} hosts changed · +{{.Summary.IPsAdded}} / −{{.Summary.IPsRemoved}} IPs · {{.Summary.DNSChanges}} apex DNS changes · +{{.Summary.CertsAdded}} certificates · {{.Summary.ProviderChanges}} provider changes</td></tr>{{end}}
        <tr><td><strong>Cloud / hosting / CDN</strong> <small>(inferred)</small></td><td>{{range $i, $c := .Aggregates.ByCloud}}{{if $i}} · {{end}}{{$c.Name}} ({{$c.Count}}){{else}}—{{end}}</td></tr>
        <tr><td><strong>ASNs</strong></td><td>{{range $i, $a := .Aggregates.ByASN}}{{if $i}} · {{end}}{{$a.ASN}} {{$a.Name}}{{else}}—{{end}}</td></tr>
        <tr><td><strong>Countries</strong> <small>(ip-api; approximate)</small></td><td>{{range $i, $c := .Aggregates.ByCountry}}{{if $i}} · {{end}}{{$c.Name}}{{else}}—{{end}}</td></tr>
        {{with .Email}}<tr><td><strong>Email providers</strong> <small>(inferred)</small></td><td>{{if .MailProviders}}{{join .MailProviders ", "}}{{else}}—{{end}}</td></tr>{{end}}
        <tr><td><strong>Certificate health</strong></td><td>{{.CertSummary.Total}} certificates in CT logs · {{.CertSummary.Valid}} valid · {{.CertSummary.Lt7}} expire &lt;7d · {{add .CertSummary.Lt14 .CertSummary.Lt30}} expire 7–30d · {{.CertSummary.Expired}} expired</td></tr>
        <tr><td><strong>DNS security</strong></td><td>DNSSEC: {{if .DNSSEC}}{{.DNSSEC.Status}}{{else}}—{{end}} · CAA: {{if .CAA}}{{.CAA.Posture}}{{else}}—{{end}}</td></tr>
        {{with .Email}}<tr><td><strong>Email security</strong></td><td>Score {{.Score}}/{{.MaxScore}} · SPF {{yesno .SPF.Present}}{{if .SPF.All}} ({{.SPF.All}}){{end}} · DKIM {{if .DKIM.Found}}found{{else}}not found (inconclusive){{end}} · DMARC {{if .DMARC.Present}}p={{.DMARC.Policy}}{{else}}missing{{end}} · MTA-STS {{yesno .MTASTS.Present}} · TLS-RPT {{yesno .TLSRPT.Present}}</td></tr>{{end}}
        <tr><td><strong>Investigation priority</strong></td><td>{{.Aggregates.HighInterest}} high-interest hosts{{if .Dangling}} · {{len .Dangling}} potential dangling DNS indicators{{end}} — indicators for review, not confirmed vulnerabilities</td></tr>
      </tbody>
    </table>
  </div>

  {{with .Changes}}{{if .Events}}
  <h2 class="section-title">Changes Since Previous Scan</h2>
  <table>
    <thead><tr><th>Change</th><th>Category</th><th>Object</th><th>Before</th><th>After</th></tr></thead>
    <tbody>{{range .Events}}<tr><td>{{.Action}}</td><td>{{.Category}}</td><td><strong>{{.Key}}</strong></td><td>{{.Old}}</td><td>{{.New}}</td></tr>{{end}}</tbody>
  </table>
  {{end}}{{end}}

  <h2 class="section-title">Attack Surface — Subdomains</h2>
  <p><small>Status/IPs/sources are <em>observed</em>; ASN/org/country are <em>enriched</em>; cloud, CDN, likely role and interest are <em>inferred</em> and require verification. "Resolves" means the name currently resolves in public DNS.</small></p>
  <table>
    <thead><tr><th>Hostname</th><th>Lifecycle</th><th>DNS</th><th>Confidence</th><th>Sources</th><th>First / last seen</th><th>IPs</th><th>ASN / Org</th><th>Cloud / CDN</th><th>Likely role</th><th>Certs</th><th>Interest</th></tr></thead>
    <tbody>
      {{range .Hosts}}
      <tr>
        <td><strong>{{.Hostname}}</strong>{{if .Indicators}}<br><small>{{join .Indicators ", "}}</small>{{end}}{{with .Web}}<br><small title="Archived third-party capture (urlscan.io), {{day .CapturedAt}}">urlscan: {{if .Title}}“{{.Title}}”{{else}}(no title){{end}}{{if .Server}} · {{.Server}}{{end}}{{if .HTTPStatus}} · {{.HTTPStatus}}{{end}}{{if .Technologies}} · {{join .Technologies ", "}}{{end}} · <a href="{{.ScanURL}}" target="_blank" rel="noopener">scan</a>{{if .Screenshot}} · <a href="{{.Screenshot}}" target="_blank" rel="noopener">screenshot</a>{{end}}</small>{{end}}{{if .CodeRefs}}<br><small>in code: {{range $i, $u := .CodeRefs}}{{if $i}} · {{end}}<a href="{{$u}}" target="_blank" rel="noopener">GitHub {{add $i 1}}</a>{{end}}</small>{{end}}</td>
        <td>{{.Lifecycle}}</td>
        <td>{{if eq .DNSStatus "resolves"}}<span class="badge badge-live">RESOLVES</span>{{else}}<span class="badge badge-off">{{.DNSStatus}}</span>{{end}}</td>
        <td>{{.Confidence}} ({{.ConfidenceLevel}})</td>
        <td>{{join .Sources ", "}}</td>
        <td>{{day .FirstSeen}} → {{day .LastSeen}}<br><small>{{.Recency}}</small></td>
        <td>{{join .IPs ", "}}{{if .CNAMEs}}<br><small>CNAME → {{join .CNAMEs " → "}}</small>{{end}}</td>
        <td>{{.ASN}}<br><small>{{.Organization}}</small></td>
        <td>{{.CDN}}{{if and .CDN .Cloud}}<br>{{end}}{{.Cloud}}</td>
        <td>{{.Role}}</td>
        <td>{{.Certificates}}</td>
        <td>{{.Interest}} ({{.InterestScore}})</td>
      </tr>
      {{end}}
    </tbody>
  </table>

  {{if .Dangling}}
  <h2 class="section-title">Potential Dangling DNS (requires verification)</h2>
  <table>
    <thead><tr><th>Hostname</th><th>CNAME target</th><th>Service</th><th>Reason</th></tr></thead>
    <tbody>{{range .Dangling}}<tr><td><strong>{{.Hostname}}</strong></td><td><code>{{.CNAME}}</code></td><td>{{.Service}}</td><td>{{.Reason}}</td></tr>{{end}}</tbody>
  </table>
  {{end}}

  {{with .Email}}
  <h2 class="section-title">Email Security</h2>
  <table>
    <thead><tr><th>Control</th><th>Points</th><th>Assessment</th></tr></thead>
    <tbody>{{range .ScoreBreakdown}}<tr><td><strong>{{.Control}}</strong></td><td>{{.Points}}/{{.Max}}</td><td>{{.Reason}}</td></tr>{{end}}</tbody>
  </table>
  <p><small>Score {{.Score}}/{{.MaxScore}}: fixed points per control (SPF 25, DMARC 30, DKIM 20, MTA-STS 15, TLS-RPT 10). DKIM is excluded from the maximum when no key is found at well-known selectors, because custom selectors cannot be discovered passively.</small></p>
  <table>
    <tbody>
      <tr><td><strong>SPF</strong></td><td>{{if .SPF.Present}}<code>{{.SPF.Raw}}</code><br>{{.SPF.Policy}} · {{.SPF.LookupCount}}/10 DNS lookups{{if .SPF.Senders}} · senders: {{join .SPF.Senders ", "}}{{end}}{{range .SPF.Issues}}<br>⚠ {{.}}{{end}}{{else}}No SPF record{{end}}</td></tr>
      <tr><td><strong>DMARC</strong></td><td>{{if .DMARC.Present}}<code>{{.DMARC.Raw}}</code><br>{{.DMARC.Posture}} · sp={{.DMARC.SubdomainPolicy}} · pct={{.DMARC.Pct}} · adkim={{.DMARC.ADKIM}} · aspf={{.DMARC.ASPF}}{{range .DMARC.Issues}}<br>⚠ {{.}}{{end}}{{else}}{{.DMARC.Posture}}{{end}}</td></tr>
      <tr><td><strong>DKIM</strong></td><td>{{range .DKIM.Found}}<code>{{.Selector}}._domainkey</code> {{.KeyType}}{{if .KeyBits}} {{.KeyBits}}-bit{{end}}{{if .Service}} ({{.Service}}){{end}}{{if .Revoked}} — revoked{{end}}<br>{{else}}No key at {{len .DKIM.Checked}} well-known selectors (inconclusive){{end}}</td></tr>
      <tr><td><strong>MTA-STS</strong></td><td>{{if .MTASTS.Present}}<code>{{.MTASTS.Raw}}</code><br><small>{{.MTASTS.Note}}</small>{{else}}Not published{{end}}</td></tr>
      <tr><td><strong>TLS-RPT</strong></td><td>{{if .TLSRPT.Present}}<code>{{.TLSRPT.Raw}}</code>{{else}}Not published{{end}}</td></tr>
    </tbody>
  </table>
  {{end}}
  {{if .MailServers}}
  <table>
    <thead><tr><th>MX host</th><th>Priority</th><th>IPs</th><th>ASN / Org</th><th>Country</th><th>Likely provider</th></tr></thead>
    <tbody>{{range .MailServers}}<tr><td>{{.Hostname}}</td><td>{{.Priority}}</td><td>{{join .IPs ", "}}</td><td>{{.ASN}}</td><td>{{.Country}}</td><td>{{.Provider}}</td></tr>{{end}}</tbody>
  </table>
  {{end}}

  <h2 class="section-title">DNS Security</h2>
  <table>
    <tbody>
      {{with .DNSSEC}}<tr><td><strong>DNSSEC</strong></td><td>{{.Status}}{{if .Algorithms}} · {{join .Algorithms ", "}}{{end}}{{range .DS}}<br>DS key tag {{.KeyTag}} · {{.Algorithm}} · {{.DigestType}}{{end}}</td></tr>{{end}}
      {{with .CAA}}<tr><td><strong>CAA</strong></td><td>{{.Posture}}{{if .Issue}} · issue: {{join .Issue ", "}}{{end}}{{if .IssueWild}} · issuewild: {{join .IssueWild ", "}}{{end}}{{range .Notes}}<br>{{.}}{{end}}</td></tr>{{end}}
      {{if .Nameservers}}<tr><td><strong>Nameservers</strong></td><td>{{range .Nameservers}}{{.Hostname}} — {{.ASN}}{{if .Provider}} (likely {{.Provider}}){{end}}<br>{{end}}</td></tr>{{end}}
    </tbody>
  </table>

  <h2 class="section-title">Certificates (Certificate Transparency)</h2>
  <p>{{.CertSummary.Total}} certificates · {{.CertSummary.Valid}} valid · {{.CertSummary.Expired}} expired · {{.CertSummary.Wildcard}} wildcard · oldest issued {{.CertSummary.OldestSeen}}{{if gt .CertSummary.Total .CertSummary.Listed}} · showing the {{.CertSummary.Listed}} most recent{{end}}</p>
  <table>
    <thead><tr><th>crt.sh</th><th>Common name</th><th>Issuer</th><th>SANs</th><th>Not before</th><th>Not after</th><th>Expiry</th><th>Indicators</th></tr></thead>
    <tbody>{{range .Certificates}}<tr><td>#{{.ID}}</td><td>{{.CommonName}}</td><td>{{.Issuer}}</td><td><small>{{join .SANs ", "}}</small></td><td>{{.NotBefore.Format "2006-01-02"}}</td><td>{{.NotAfter.Format "2006-01-02"}}</td><td>{{.ExpiryStatus}}</td><td>{{join .Indicators ", "}}</td></tr>{{end}}</tbody>
  </table>

  <h2 class="section-title">Infrastructure — IP Addresses</h2>
  <table>
    <thead><tr><th>IP</th><th>Hostnames</th><th>ASN</th><th>Prefix / RIR</th><th>Routing cross-check</th><th>Organization</th><th>Location</th><th>Reverse DNS</th><th>Likely provider</th></tr></thead>
    <tbody>{{range .IPs}}<tr><td><code>{{.IP}}</code></td><td><small>{{join .Hostnames ", "}}</small></td><td>{{.ASN}}</td><td>{{.Prefix}} {{.RIR}}</td><td>{{with .Routing}}{{if eq .Agreement "disagree"}}<strong style="color:var(--orange)">⚠ disagree</strong><br><small>{{join .Conflicts "; "}}</small>{{else if eq .Agreement "agree"}}✓ RIPEstat agrees{{else}}RIPEstat only{{end}}{{if .Upstreams}}<br><small>upstreams: {{join .Upstreams ", "}}</small>{{end}}{{else}}—{{end}}</td><td>{{.Organization}}</td><td>{{.City}}{{if .City}}, {{end}}{{.Country}}</td><td><small>{{.ReverseDNS}}</small></td><td>{{.Provider}}</td></tr>{{end}}</tbody>
  </table>

  {{if .Aggregates.ExposedIPs}}
  <h2 class="section-title">Exposure — Shodan InternetDB</h2>
  <p><small>{{.Aggregates.ExposedIPs}} of {{.Aggregates.UniqueIPs}} IPs are in Shodan's index · {{.Aggregates.OpenPorts}} open ports · {{.Aggregates.ReportedCVEs}} distinct CVE IDs, {{.Aggregates.KEVCVEs}} in CISA KEV. CVEs are ordered KEV first, then by EPSS (Shodan CVEDB). This is Shodan's most recent crawl, not a live check; CVE IDs are matched from software versions and are <em>unverified indicators</em>, not confirmed vulnerabilities.</small></p>
  <table>
    <thead><tr><th>IP</th><th>Hostnames (this scan)</th><th>Open ports</th><th>CPEs</th><th>Tags</th><th>Reported CVEs</th></tr></thead>
    <tbody>{{range $ip := .IPs}}{{with $ip.Exposure}}<tr><td><code>{{$ip.IP}}</code></td><td><small>{{join $ip.Hostnames ", "}}</small></td><td>{{ports .Ports}}</td><td><small>{{join .CPEs ", "}}</small></td><td>{{join .Tags ", "}}</td><td><small>{{cves .Vulns 10}}</small></td></tr>{{end}}{{end}}</tbody>
  </table>
  {{end}}

  {{if .Providers}}
  <h2 class="section-title">Third-Party & Provider Map (inferred)</h2>
  <table>
    <thead><tr><th>Category</th><th>Likely provider</th><th>Hosts</th><th>Evidence</th></tr></thead>
    <tbody>{{range .Providers}}<tr><td>{{.Category}}</td><td>{{.Name}}</td><td>{{.Hosts}}</td><td><small>{{join .Evidence " · "}}</small></td></tr>{{end}}</tbody>
  </table>
  {{end}}

  <h2 class="section-title">Sources</h2>
  <table>
    <thead><tr><th>Source</th><th>Purpose</th><th>Status</th><th>Duration</th><th>Results</th><th>Reliability</th><th>Error / note</th></tr></thead>
    <tbody>{{range .Sources}}<tr><td><strong>{{.Name}}</strong></td><td>{{.Purpose}}</td><td>{{.Status}}</td><td>{{ms .DurationMs}}</td><td>{{.Results}}</td><td>{{.Reliability}}</td><td><small>{{.Error}}</small></td></tr>{{end}}</tbody>
  </table>
{{end}}{{end}}`
