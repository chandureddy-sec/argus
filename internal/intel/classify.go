package intel

import (
	"fmt"
	"math"
	"strings"
	"time"

	"reconx/pkg/models"
)

// roleRules map hostname labels to a likely role, in priority order: when a
// hostname matches several, the earlier (more security-relevant) role wins.
var roleRules = []struct {
	role   string
	labels []string
}{
	{"Administrative", []string{"admin", "administrator", "cpanel", "whm", "plesk", "backoffice", "manage", "management", "console", "dashboard", "panel", "phpmyadmin"}},
	{"Authentication", []string{"auth", "login", "sso", "signin", "oauth", "idp", "adfs", "identity", "okta", "keycloak", "cas", "accounts"}},
	{"VPN / Remote Access", []string{"vpn", "remote", "citrix", "rdp", "rdweb", "anyconnect", "globalprotect", "fortigate", "pulse", "ssl-vpn", "sslvpn", "vdi", "bastion", "jump"}},
	{"CI/CD", []string{"jenkins", "gitlab", "git", "ci", "cd", "build", "builds", "drone", "bamboo", "teamcity", "argocd", "argo", "sonar", "sonarqube", "nexus", "artifactory", "registry", "docker", "harbor"}},
	{"Monitoring", []string{"grafana", "kibana", "prometheus", "monitor", "monitoring", "nagios", "zabbix", "metrics", "logs", "logging", "elk", "splunk", "sentry", "uptime", "apm"}},
	{"Staging", []string{"staging", "stage", "stg", "preprod", "pre-prod", "uat"}},
	{"Testing", []string{"test", "testing", "qa", "sandbox", "demo", "beta", "alpha", "trial"}},
	{"Development", []string{"dev", "develop", "development", "devel", "local", "lab", "labs"}},
	{"Email", []string{"mail", "smtp", "imap", "pop", "pop3", "webmail", "mx", "owa", "exchange", "autodiscover", "autoconfig", "mta-sts", "email"}},
	{"API", []string{"api", "apis", "graphql", "rest", "ws", "wss", "backend", "gateway", "rpc", "grpc"}},
	{"Storage", []string{"s3", "storage", "bucket", "blob", "backup", "backups", "ftp", "sftp", "files", "upload", "uploads"}},
	{"Documentation", []string{"docs", "doc", "documentation", "wiki", "help", "kb", "developer", "developers", "confluence", "support", "helpdesk", "servicedesk"}},
	{"Status", []string{"status", "statuspage", "health"}},
	{"Customer Portal", []string{"portal", "my", "customer", "customers", "client", "clients", "account", "app", "apps", "shop", "store", "billing"}},
	{"CDN", []string{"cdn", "edge", "cache"}},
	{"Static", []string{"static", "assets", "img", "images", "media", "download", "downloads", "content"}},
	{"Web", []string{"www", "web", "site", "home", "blog", "news", "info"}},
}

// indicatorLabels are hostname words worth a closer look. They are
// investigation hints, never evidence of a vulnerability.
var indicatorLabels = map[string]bool{
	"admin": true, "administrator": true, "portal": true, "vpn": true, "login": true, "auth": true,
	"sso": true, "api": true, "staging": true, "stage": true, "dev": true, "test": true, "qa": true,
	"uat": true, "jenkins": true, "gitlab": true, "grafana": true, "kibana": true, "jira": true,
	"confluence": true, "registry": true, "docker": true, "monitoring": true, "internal": true,
	"legacy": true, "old": true, "backup": true, "sandbox": true, "beta": true, "preprod": true,
	"phpmyadmin": true, "intranet": true, "corp": true,
}

// labelsOf splits the host part left of the target domain into words, e.g.
// "dev-api2.eu.example.com" -> [dev api eu].
func labelsOf(host, domain string) []string {
	h := strings.TrimSuffix(strings.ToLower(host), "."+strings.ToLower(domain))
	if h == strings.ToLower(domain) {
		return nil
	}
	f := strings.FieldsFunc(h, func(r rune) bool { return r == '.' || r == '-' || r == '_' })
	out := make([]string, 0, len(f))
	for _, w := range f {
		w = strings.TrimRight(w, "0123456789")
		if w != "" {
			out = append(out, w)
		}
	}
	return out
}

// Classify returns the likely role of a hostname and the indicator words it
// contains. The role is an inference from naming only.
func Classify(host, domain string) (role string, indicators []string) {
	labels := labelsOf(host, domain)
	if strings.EqualFold(host, domain) {
		return "Web (apex)", nil
	}
	set := make(map[string]bool, len(labels))
	for _, l := range labels {
		set[l] = true
		if indicatorLabels[l] && !contains(indicators, l) {
			indicators = append(indicators, l)
		}
	}
	for _, rr := range roleRules {
		for _, l := range rr.labels {
			if set[l] {
				return rr.role, indicators
			}
		}
	}
	// Fallback for run-together names ("winremote", "devjenkins"): match the
	// longer keywords inside a label. Short words are skipped to avoid false
	// hits such as "mx" inside an unrelated word.
	for _, rr := range roleRules {
		for _, kw := range rr.labels {
			if len(kw) < 5 {
				continue
			}
			for _, l := range labels {
				if l != kw && strings.Contains(l, kw) {
					return rr.role, indicators
				}
			}
		}
	}
	return "Unknown", indicators
}

var sensitiveRoles = map[string]bool{"Administrative": true, "Authentication": true, "VPN / Remote Access": true, "CI/CD": true, "Monitoring": true}
var nonProdRoles = map[string]bool{"Staging": true, "Testing": true, "Development": true}

// ScoreInterest computes the investigation-priority score for a host. It
// ranks hosts for review; it is not a vulnerability or severity score.
func ScoreInterest(h *models.HostIntel, dangling bool) {
	score := 0
	var f []string
	add := func(pts int, why string) {
		score += pts
		f = append(f, fmt.Sprintf("%+d %s", pts, why))
	}
	switch {
	case sensitiveRoles[h.Role]:
		add(3, "sensitive role ("+h.Role+")")
	case nonProdRoles[h.Role]:
		add(2, "non-production environment ("+h.Role+")")
	case h.Role == "API":
		add(2, "API endpoint")
	}
	if n := len(h.Indicators); n > 0 {
		pts := n
		if pts > 2 {
			pts = 2
		}
		add(pts, "indicator words: "+strings.Join(h.Indicators, ", "))
	}
	if h.DNSStatus == "resolves" {
		if sensitiveRoles[h.Role] || nonProdRoles[h.Role] || h.Role == "API" {
			add(2, "currently resolves (publicly reachable name)")
		} else {
			add(1, "currently resolves")
		}
	}
	if dangling {
		add(3, "potential dangling CNAME")
	}
	if h.Lifecycle == "new" {
		add(1, "new since previous scan")
	}
	if h.Lifecycle == "changed" {
		add(1, "DNS changed since previous scan")
	}
	if h.ConfidenceLevel == "low" {
		add(-1, "low confidence")
	}
	h.InterestScore = score
	h.InterestFactors = f
	setInterestLevel(h)
}

// ── Confidence & recency ─────────────────────────────────────────────────────

// sourceReliability is the internal trust weight for each source.
var sourceReliability = map[string]struct {
	level  string
	weight float64
}{
	"dns":          {models.ReliabilityHigh, 0.95},
	"crtsh":        {models.ReliabilityHigh, 0.90},
	"rdap":         {models.ReliabilityHigh, 0.90},
	"alienvault":   {models.ReliabilityMediumHigh, 0.80},
	"reconx":       {models.ReliabilityHigh, 0.85},
	"hackertarget": {models.ReliabilityMedium, 0.65},
	"anubis":       {models.ReliabilityMedium, 0.60},
	"wayback":      {models.ReliabilityMedium, 0.60},
	"urlscan":      {models.ReliabilityMediumHigh, 0.75}, // a real page load, but by a third party at some past date
	"certspotter":  {models.ReliabilityHigh, 0.90},       // CT log entries, like crt.sh
	"githubcode":   {models.ReliabilityMedium, 0.55},     // a mention in code; may be stale, a typo or an example
	"ip-api":       {models.ReliabilityMedium, 0.70},     // geolocation is approximate
	"team-cymru":   {models.ReliabilityHigh, 0.90},       // BGP-derived

	"shodan-internetdb": {models.ReliabilityMediumHigh, 0.80}, // crawl snapshot, may be days old
	"ripestat":          {models.ReliabilityHigh, 0.90},       // BGP-derived (RIPE RIS)
}

// Reliability returns the reliability level for a source name.
func Reliability(source string) string {
	if r, ok := sourceReliability[source]; ok {
		return r.level
	}
	return models.ReliabilityLow
}

func reliabilityWeight(source string) float64 {
	if r, ok := sourceReliability[source]; ok {
		return r.weight
	}
	return 0.5
}

// recencyFactor discounts older evidence: a capture from years ago supports
// existence less than a current observation.
func recencyFactor(last *time.Time, now time.Time) float64 {
	if last == nil {
		return 0.8
	}
	age := now.Sub(*last)
	switch {
	case age <= 90*24*time.Hour:
		return 1.0
	case age <= 365*24*time.Hour:
		return 0.9
	case age <= 3*365*24*time.Hour:
		return 0.7
	default:
		return 0.5
	}
}

// ScoreConfidence combines independent evidence into a 0-100 confidence that
// the hostname is (or was) a real asset of the target:
//
//	confidence = 1 − Π (1 − reliability_i × recency_i)
//
// over every source that reported the host, plus current DNS resolution.
func ScoreConfidence(h *models.HostIntel, now time.Time) {
	miss := 1.0
	for _, ev := range h.Evidence {
		miss *= 1 - reliabilityWeight(ev.Source)*recencyFactor(ev.LastSeen, now)
	}
	if h.DNSStatus == "resolves" {
		miss *= 1 - reliabilityWeight("dns")
	}
	h.Confidence = int(math.Round((1 - miss) * 100))
	switch {
	case h.Confidence >= 85:
		h.ConfidenceLevel = "high"
	case h.Confidence >= 60:
		h.ConfidenceLevel = "medium"
	default:
		h.ConfidenceLevel = "low"
	}
}

// ClassifyRecency labels how current the evidence for a host is. Only current
// DNS resolution makes a host "current"; CT or archive sightings alone never do.
func ClassifyRecency(h *models.HostIntel, now time.Time) {
	if h.DNSStatus == "resolves" {
		h.Recency = "current"
		return
	}
	if h.LastSeen == nil {
		h.Recency = "historical"
		return
	}
	age := now.Sub(*h.LastSeen)
	switch {
	case age <= 90*24*time.Hour:
		h.Recency = "recent"
	case age <= 2*365*24*time.Hour:
		h.Recency = "historical"
	default:
		h.Recency = "stale"
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// AddExposureInterest raises a host's interest when one of its current IPs
// has a CVE that Shodan reports and CISA lists as known-exploited. The CVE
// match is Shodan's version-based inference, so it is labelled unverified.
func AddExposureInterest(h *models.HostIntel, kevByIP map[string][]string) {
	var ids []string
	for _, ip := range h.IPs {
		ids = append(ids, kevByIP[ip]...)
	}
	ids = dedupe(ids)
	if len(ids) == 0 {
		return
	}
	shown := ids
	if len(shown) > 3 {
		shown = shown[:3]
	}
	h.InterestScore += 2
	h.InterestFactors = append(h.InterestFactors, fmt.Sprintf("%+d IP has CISA KEV-listed CVE reported by Shodan (unverified): %s", 2, strings.Join(shown, ", ")))
	setInterestLevel(h)
}

func setInterestLevel(h *models.HostIntel) {
	switch {
	case h.InterestScore >= 5:
		h.Interest = "high"
	case h.InterestScore >= 3:
		h.Interest = "medium"
	default:
		h.Interest = "low"
	}
}
