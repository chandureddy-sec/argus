package monitor

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"reconx/internal/history"
	"reconx/pkg/models"
)

// Alert severities, highest first.
const (
	SevHigh   = "high"
	SevMedium = "medium"
	SevLow    = "low"
	SevInfo   = "info"
)

var sevRank = map[string]int{SevHigh: 0, SevMedium: 1, SevLow: 2, SevInfo: 3}

// AtLeast reports whether sev is at or above min.
func AtLeast(sev, min string) bool {
	r, ok := sevRank[sev]
	m, ok2 := sevRank[min]
	return ok && ok2 && r <= m
}

// Alert rules. Each produces at most one alert per run, listing every item.
const (
	RuleSubdomainAdded   = "subdomain_added"
	RuleSubdomainRemoved = "subdomain_removed"
	RuleDNSChanged       = "dns_changed"
	RuleCertIssued       = "certificate_issued"
	RuleCertExpiring     = "certificate_expiring"
	RuleProviderChanged  = "provider_changed"
	RuleExposure         = "exposure_changed"
	RuleDangling         = "dangling_dns"
	RuleEmailPosture     = "email_posture"
)

// Rules describes every rule, for the CLI and dashboard.
var Rules = []struct{ ID, Description string }{
	{RuleSubdomainAdded, "New subdomains appear (high when a new host scores high interest)"},
	{RuleSubdomainRemoved, "Subdomains disappear from every source"},
	{RuleDNSChanged, "A host's A/AAAA/CNAME or the apex DNS records change"},
	{RuleCertIssued, "New certificates are logged in Certificate Transparency"},
	{RuleCertExpiring, "A valid certificate crosses the 14-day or 7-day expiry threshold"},
	{RuleProviderChanged, "Cloud / CDN / email providers or ASNs are added or removed"},
	{RuleExposure, "Shodan reports new open ports or CVE IDs (KEV-listed CVEs are high)"},
	{RuleDangling, "A new potential dangling-DNS indicator appears"},
	{RuleEmailPosture, "SPF, DMARC or the email-security score weakens"},
}

// ValidateRules rejects unknown rule IDs.
func ValidateRules(rules []string) error {
	for _, r := range rules {
		ok := false
		for _, k := range Rules {
			if k.ID == r {
				ok = true
			}
		}
		if !ok {
			return fmt.Errorf("unknown alert rule %q", r)
		}
	}
	return nil
}

// Alert is one notification about a change in a monitored target.
type Alert struct {
	ID        string    `json:"id"`
	MonitorID string    `json:"monitor_id"`
	Target    string    `json:"target"`
	Time      time.Time `json:"time"`
	Rule      string    `json:"rule"`
	Severity  string    `json:"severity"`
	Title     string    `json:"title"`
	Items     []string  `json:"items,omitempty"`
	More      int       `json:"more,omitempty"`      // items left out of Items
	ScanFile  string    `json:"scan_file,omitempty"` // reports/ JSON of the run that raised it
	Baseline  string    `json:"baseline_file,omitempty"`
	Delivered string    `json:"delivered,omitempty"` // webhook outcome: sent | failed: … | skipped
}

const maxItems = 25

// Evaluate compares a run with the previous saved scan of the target and
// returns the alerts the enabled rules raise. prev may be nil (first run).
func Evaluate(m *Monitor, prev, cur *models.ScanReport, prevFile, curFile string) []Alert {
	now := time.Now().UTC()
	mk := func(rule, sev, title string, items []string) Alert {
		a := Alert{ID: newID(), MonitorID: m.ID, Target: m.Target, Time: now, Rule: rule, Severity: sev, Title: title, ScanFile: curFile, Baseline: prevFile}
		sort.Strings(items)
		if len(items) > maxItems {
			a.More = len(items) - maxItems
			items = items[:maxItems]
		}
		a.Items = items
		return a
	}
	if prev == nil {
		return []Alert{mk("baseline", SevInfo, fmt.Sprintf("Monitoring started for %s — baseline scan saved", m.Target), nil)}
	}

	enabled := func(rule string) bool {
		if len(m.Rules) == 0 {
			return true
		}
		for _, r := range m.Rules {
			if r == rule {
				return true
			}
		}
		return false
	}
	var out []Alert
	add := func(rule, sev, title string, items []string) {
		if enabled(rule) && len(items) > 0 {
			out = append(out, mk(rule, sev, title, items))
		}
	}

	cs := history.Compare(prev, cur, prevFile, curFile)
	var added, removed, dnsChg, certNew, provChg []string
	for _, e := range cs.Events {
		switch {
		case e.Category == "subdomain" && e.Action == "added":
			added = append(added, e.Key)
		case e.Category == "subdomain" && e.Action == "removed":
			removed = append(removed, e.Key)
		case e.Category == "dns":
			dnsChg = append(dnsChg, fmt.Sprintf("%s: %s → %s", e.Key, e.Old, e.New))
		case e.Category == "certificate" && e.Action == "added":
			certNew = append(certNew, e.Key+" · "+e.New)
		case e.Category == "provider":
			provChg = append(provChg, strings.TrimSpace(e.Action+" "+e.Key+" "+e.New))
		}
	}

	sev := SevMedium
	if hi := highInterest(cur, added); len(hi) > 0 {
		sev = SevHigh
		for i, h := range added {
			if hi[h] {
				added[i] = h + " (high interest)"
			}
		}
	}
	add(RuleSubdomainAdded, sev, plural(len(added), "new subdomain", "new subdomains")+" on "+m.Target, added)
	add(RuleSubdomainRemoved, SevLow, plural(len(removed), "subdomain", "subdomains")+" no longer reported for "+m.Target, removed)
	add(RuleDNSChanged, SevMedium, plural(len(dnsChg), "DNS change", "DNS changes")+" on "+m.Target, dnsChg)
	add(RuleCertIssued, SevInfo, plural(len(certNew), "new certificate", "new certificates")+" for "+m.Target, certNew)
	add(RuleProviderChanged, SevLow, plural(len(provChg), "provider change", "provider changes")+" for "+m.Target, provChg)

	if exp, high := certExpiry(prev, cur); len(exp) > 0 {
		s := SevMedium
		if high {
			s = SevHigh
		}
		add(RuleCertExpiring, s, plural(len(exp), "certificate", "certificates")+" for "+m.Target+" expiring soon", exp)
	}
	if items, kev := exposureChanges(prev, cur); len(items) > 0 {
		s := SevMedium
		if kev {
			s = SevHigh
		}
		add(RuleExposure, s, "New exposure reported by Shodan on "+m.Target, items)
	}
	add(RuleDangling, SevHigh, "New potential dangling DNS on "+m.Target+" (verify — not a confirmed takeover)", newDangling(prev, cur))
	add(RuleEmailPosture, SevMedium, "Email security weakened on "+m.Target, emailRegressions(prev, cur))

	sort.SliceStable(out, func(i, j int) bool { return sevRank[out[i].Severity] < sevRank[out[j].Severity] })
	return out
}

func highInterest(cur *models.ScanReport, hosts []string) map[string]bool {
	out := map[string]bool{}
	if cur.Intel == nil {
		return out
	}
	want := map[string]bool{}
	for _, h := range hosts {
		want[h] = true
	}
	for _, h := range cur.Intel.Hosts {
		if want[h.Hostname] && h.Interest == "high" {
			out[h.Hostname] = true
		}
	}
	return out
}

// certExpiry lists certificates that were outside a threshold in prev and are
// inside it now, so a certificate alerts once per threshold, not every run.
func certExpiry(prev, cur *models.ScanReport) ([]string, bool) {
	if cur.Intel == nil {
		return nil, false
	}
	before := map[int64]string{}
	if prev.Intel != nil {
		for _, c := range prev.Intel.Certificates {
			before[c.ID] = c.ExpiryStatus
		}
	}
	rank := map[string]int{"ok": 0, "lt30": 1, "lt14": 2, "lt7": 3, "expired": 4}
	var out []string
	high := false
	for _, c := range cur.Intel.Certificates {
		if c.ExpiryStatus != "lt14" && c.ExpiryStatus != "lt7" {
			continue
		}
		old, seen := before[c.ID]
		if seen && rank[old] >= rank[c.ExpiryStatus] {
			continue
		}
		days := int(time.Until(c.NotAfter).Hours() / 24)
		name := firstNonEmpty(c.CommonName, first(c.SANs))
		out = append(out, fmt.Sprintf("%s expires %s (%d days) · crt.sh #%d", name, c.NotAfter.Format("2006-01-02"), days, c.ID))
		if c.ExpiryStatus == "lt7" {
			high = true
		}
	}
	return out, high
}

// exposureChanges lists ports and CVE IDs Shodan reports now but did not for
// the same IP in prev. IPs new to the scan count in full.
func exposureChanges(prev, cur *models.ScanReport) ([]string, bool) {
	if cur.Intel == nil {
		return nil, false
	}
	type seen struct{ ports, cves map[string]bool }
	old := map[string]seen{}
	if prev.Intel != nil {
		for _, ip := range prev.Intel.IPs {
			s := seen{map[string]bool{}, map[string]bool{}}
			if ip.Exposure != nil {
				for _, p := range ip.Exposure.Ports {
					s.ports[fmt.Sprint(p)] = true
				}
				for _, v := range ip.Exposure.Vulns {
					s.cves[v.ID] = true
				}
			}
			old[ip.IP] = s
		}
	}
	domain := ""
	if cur.Target != nil {
		domain = strings.ToLower(cur.Target.Value)
	}
	var out []string
	kev := false
	for _, ip := range cur.Intel.IPs {
		// Nameserver / MX IPs (Cloudflare NS, Google SMTP…) are the provider's
		// infrastructure and rotate between scans; only alert on IPs that
		// serve the target's own hostnames.
		if ip.Exposure == nil || !servesDomain(ip.Hostnames, domain) {
			continue
		}
		o := old[ip.IP]
		var ports, cves []string
		for _, p := range ip.Exposure.Ports {
			if !o.ports[fmt.Sprint(p)] {
				ports = append(ports, fmt.Sprint(p))
			}
		}
		for _, v := range ip.Exposure.Vulns {
			if o.cves[v.ID] {
				continue
			}
			label := v.ID
			if v.KEV {
				label += " (CISA KEV)"
				kev = true
			}
			cves = append(cves, label)
		}
		host := ""
		if len(ip.Hostnames) > 0 {
			host = " (" + ip.Hostnames[0] + ")"
		}
		if len(ports) > 0 {
			out = append(out, fmt.Sprintf("%s%s: new open ports %s", ip.IP, host, strings.Join(ports, ", ")))
		}
		if len(cves) > 0 {
			out = append(out, fmt.Sprintf("%s%s: newly reported CVEs %s (unverified, version-based)", ip.IP, host, strings.Join(cves, ", ")))
		}
	}
	return out, kev
}

func servesDomain(hostnames []string, domain string) bool {
	if domain == "" {
		return true
	}
	for _, h := range hostnames {
		h = strings.ToLower(h)
		if h == domain || strings.HasSuffix(h, "."+domain) {
			return true
		}
	}
	return false
}

func newDangling(prev, cur *models.ScanReport) []string {
	if cur.Intel == nil {
		return nil
	}
	old := map[string]bool{}
	if prev.Intel != nil {
		for _, d := range prev.Intel.Dangling {
			old[d.Hostname+"|"+d.CNAME] = true
		}
	}
	var out []string
	for _, d := range cur.Intel.Dangling {
		if !old[d.Hostname+"|"+d.CNAME] {
			out = append(out, fmt.Sprintf("%s → %s (%s)", d.Hostname, d.CNAME, d.Reason))
		}
	}
	return out
}

func emailRegressions(prev, cur *models.ScanReport) []string {
	if prev.Intel == nil || cur.Intel == nil || prev.Intel.Email == nil || cur.Intel.Email == nil {
		return nil
	}
	p, c := prev.Intel.Email, cur.Intel.Email
	var out []string
	if p.SPF.Present && !c.SPF.Present {
		out = append(out, "SPF record removed")
	}
	if p.DMARC.Present && !c.DMARC.Present {
		out = append(out, "DMARC record removed")
	}
	strength := map[string]int{"none": 0, "quarantine": 1, "reject": 2}
	if p.DMARC.Present && c.DMARC.Present && strength[c.DMARC.Policy] < strength[p.DMARC.Policy] {
		out = append(out, fmt.Sprintf("DMARC policy weakened: p=%s → p=%s", p.DMARC.Policy, c.DMARC.Policy))
	}
	if c.Score < p.Score {
		out = append(out, fmt.Sprintf("Email-security score dropped: %d/%d → %d/%d", p.Score, p.MaxScore, c.Score, c.MaxScore))
	}
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

func first(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}
