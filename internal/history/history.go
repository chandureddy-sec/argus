// Package history turns saved scan reports into a timeline for a target:
// change detection between scans, first/last-seen across scans, and the
// comparison of any two scans. Saved reports in reports/ are the source of
// truth, so history works retroactively for scans made before this existed.
package history

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"reconx/pkg/models"
)

// maxEvents caps the change events stored per scan.
const maxEvents = 500

// Scan is a saved report loaded from disk.
type Scan struct {
	File   string
	Report *models.ScanReport
}

// LoadTarget returns the saved scans of target in dir, oldest first.
func LoadTarget(dir, target string) []Scan {
	target = strings.ToLower(target)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	prefix := "recon_" + target + "_"
	var out []Scan
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(strings.ToLower(name), prefix) || !strings.HasSuffix(name, ".json") {
			continue
		}
		rep, err := Load(filepath.Join(dir, name))
		if err != nil || rep.Target == nil || !strings.EqualFold(rep.Target.Value, target) {
			continue
		}
		out = append(out, Scan{File: name, Report: rep})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Report.Timestamp.Before(out[j].Report.Timestamp) })
	return out
}

// Load reads one saved report.
func Load(path string) (*models.ScanReport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rep models.ScanReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, err
	}
	return &rep, nil
}

// HostState is the comparable DNS state of one host in a scan.
type HostState struct {
	Known    bool // whether the scan recorded resolution data for the host
	Resolves bool
	IPs      []string
	CNAMEs   []string
}

// Snapshot is the comparable state of one scan.
type Snapshot struct {
	Time      time.Time
	File      string
	Hosts     map[string]HostState
	DNS       map[string][]string // apex record type -> sorted values
	Certs     map[int64]models.CertInfo
	HasIntel  bool
	Providers map[string]bool // "Category|Name"
	ASNs      map[string]string
}

var diffTypes = map[string]bool{"A": true, "AAAA": true, "CNAME": true, "MX": true, "NS": true, "TXT": true, "CAA": true}

// FromReport builds a snapshot from a report, using passive intel when present
// and falling back to the legacy correlation graph for older reports.
func FromReport(rep *models.ScanReport, file string) Snapshot {
	s := Snapshot{
		Time: rep.Timestamp, File: file,
		Hosts: map[string]HostState{}, DNS: map[string][]string{},
		Certs: map[int64]models.CertInfo{}, Providers: map[string]bool{}, ASNs: map[string]string{},
	}
	switch {
	case rep.Intel != nil:
		s.HasIntel = true
		for _, h := range rep.Intel.Hosts {
			s.Hosts[h.Hostname] = HostState{Known: true, Resolves: h.DNSStatus == "resolves", IPs: sorted(h.IPs), CNAMEs: h.CNAMEs}
		}
		for _, c := range rep.Intel.Certificates {
			s.Certs[c.ID] = c
		}
		for _, p := range rep.Intel.Providers {
			s.Providers[p.Category+"|"+p.Name] = true
		}
		for _, ip := range rep.Intel.IPs {
			if ip.ASN != "" {
				key := strings.Fields(ip.ASN)[0]
				s.ASNs[key] = firstNonEmpty(ip.ASName, ip.Organization)
			}
		}
	case rep.Correlation != nil:
		for _, n := range rep.Correlation.Nodes {
			s.Hosts[n.Hostname] = HostState{Known: true, Resolves: n.IsAlive, IPs: sorted(n.ResolvedIPs)}
		}
	default:
		for _, a := range rep.Assets {
			s.Hosts[a.Asset] = HostState{}
		}
	}
	if rep.DNS != nil && rep.Target != nil {
		for _, r := range rep.DNS.Records {
			if !strings.EqualFold(r.Name, rep.Target.Value) || !diffTypes[r.Type] {
				continue
			}
			s.DNS[r.Type] = append(s.DNS[r.Type], normalizeDNS(r.Type, r.Value))
		}
		for t := range s.DNS {
			s.DNS[t] = sorted(s.DNS[t])
		}
	}
	return s
}

// normalizeDNS makes values comparable across parser versions (older reports
// joined multi-string TXT records with spaces).
func normalizeDNS(typ, v string) string {
	if typ == "TXT" {
		return strings.Join(strings.Fields(v), "")
	}
	return strings.ToLower(v)
}

// Diff compares two scans of the same target.
func Diff(prev, cur Snapshot) *models.ChangeSet {
	cs := &models.ChangeSet{PreviousScan: prev.Time, PreviousFile: prev.File}
	sum := &cs.Summary
	add := func(e models.ChangeEvent) {
		if len(cs.Events) < maxEvents {
			cs.Events = append(cs.Events, e)
		}
	}

	for _, h := range sortedKeys(cur.Hosts) {
		c := cur.Hosts[h]
		p, ok := prev.Hosts[h]
		if !ok {
			sum.SubdomainsAdded++
			add(models.ChangeEvent{Category: "subdomain", Action: "added", Key: h, New: strings.Join(c.IPs, ", ")})
			continue
		}
		if !p.Known || !c.Known {
			sum.Unchanged++
			continue
		}
		changed := false
		if j(p.IPs) != j(c.IPs) {
			changed = true
			add(models.ChangeEvent{Category: "dns", Action: "changed", Key: h + " A/AAAA", Old: orNone(j(p.IPs)), New: orNone(j(c.IPs))})
		}
		if prev.HasIntel && cur.HasIntel && j(p.CNAMEs) != j(c.CNAMEs) {
			changed = true
			add(models.ChangeEvent{Category: "dns", Action: "changed", Key: h + " CNAME", Old: orNone(j(p.CNAMEs)), New: orNone(j(c.CNAMEs))})
		}
		if changed {
			sum.HostsChanged++
		} else {
			sum.Unchanged++
		}
	}
	for _, h := range sortedKeys(prev.Hosts) {
		if _, ok := cur.Hosts[h]; !ok {
			sum.SubdomainsRemoved++
			add(models.ChangeEvent{Category: "subdomain", Action: "removed", Key: h, Old: strings.Join(prev.Hosts[h].IPs, ", ")})
		}
	}

	prevIPs, curIPs := ipSet(prev), ipSet(cur)
	for _, ip := range sortedKeys(curIPs) {
		if !prevIPs[ip] {
			sum.IPsAdded++
			add(models.ChangeEvent{Category: "ip", Action: "added", Key: ip})
		}
	}
	for _, ip := range sortedKeys(prevIPs) {
		if !curIPs[ip] {
			sum.IPsRemoved++
			add(models.ChangeEvent{Category: "ip", Action: "removed", Key: ip})
		}
	}

	types := map[string]bool{}
	for t := range prev.DNS {
		types[t] = true
	}
	for t := range cur.DNS {
		types[t] = true
	}
	for _, t := range sortedKeys(types) {
		if j(prev.DNS[t]) != j(cur.DNS[t]) {
			sum.DNSChanges++
			add(models.ChangeEvent{Category: "dns", Action: "changed", Key: "apex " + t, Old: orNone(j(prev.DNS[t])), New: orNone(j(cur.DNS[t]))})
		}
	}

	// Certificates are never "removed" from CT logs; report newly issued and
	// newly expired certificates instead.
	if cur.HasIntel {
		for _, c := range cur.Certs {
			if c.NotBefore.After(prev.Time) || (!c.LoggedAt.IsZero() && c.LoggedAt.After(prev.Time)) {
				if _, seen := prev.Certs[c.ID]; !seen {
					sum.CertsAdded++
					add(models.ChangeEvent{Category: "certificate", Action: "added", Key: certLabel(c), New: c.Issuer})
				}
			}
			if !c.NotAfter.IsZero() && c.NotAfter.After(prev.Time) && c.NotAfter.Before(cur.Time) {
				sum.CertsRemoved++
				add(models.ChangeEvent{Category: "certificate", Action: "expired", Key: certLabel(c), Old: c.NotAfter.Format("2006-01-02")})
			}
		}
	}

	if prev.HasIntel && cur.HasIntel {
		for _, p := range sortedKeys(cur.Providers) {
			if !prev.Providers[p] {
				sum.ProviderChanges++
				add(models.ChangeEvent{Category: "provider", Action: "added", Key: strings.Replace(p, "|", ": ", 1)})
			}
		}
		for _, p := range sortedKeys(prev.Providers) {
			if !cur.Providers[p] {
				sum.ProviderChanges++
				add(models.ChangeEvent{Category: "provider", Action: "removed", Key: strings.Replace(p, "|", ": ", 1)})
			}
		}
		for _, a := range sortedKeys(cur.ASNs) {
			if _, ok := prev.ASNs[a]; !ok {
				sum.ProviderChanges++
				add(models.ChangeEvent{Category: "provider", Action: "added", Key: "ASN " + a, New: cur.ASNs[a]})
			}
		}
	}
	return cs
}

// Apply enriches the current report's passive intel with history from the
// target's earlier saved scans: change detection against the most recent
// one, lifecycle labels, first-seen across scans, and IPs seen previously.
// prior must be oldest first and exclude the current scan.
func Apply(cur *models.ScanReport, prior []Scan) {
	pi := cur.Intel
	if pi == nil || len(prior) == 0 {
		return
	}
	curSnap := FromReport(cur, "")
	last := prior[len(prior)-1]
	lastSnap := FromReport(last.Report, last.File)
	pi.Changes = Diff(lastSnap, curSnap)

	// Per-host appearance across earlier scans.
	type seen struct {
		first, last time.Time
		ips         map[string][2]time.Time
	}
	appear := map[string]*seen{}
	for _, sc := range prior {
		snap := FromReport(sc.Report, sc.File)
		for h, st := range snap.Hosts {
			a := appear[h]
			if a == nil {
				a = &seen{first: snap.Time, ips: map[string][2]time.Time{}}
				appear[h] = a
			}
			a.last = snap.Time
			for _, ip := range st.IPs {
				w, ok := a.ips[ip]
				if !ok {
					w[0] = snap.Time
				}
				w[1] = snap.Time
				a.ips[ip] = w
			}
		}
	}

	for i := range pi.Hosts {
		h := &pi.Hosts[i]
		prevState, inLast := lastSnap.Hosts[h.Hostname]
		switch {
		case !inLast:
			h.Lifecycle = "new"
		case h.DNSStatus != "resolves":
			h.Lifecycle = "historical"
		case prevState.Known && (j(prevState.IPs) != j(sorted(h.IPs)) || (lastSnap.HasIntel && j(prevState.CNAMEs) != j(h.CNAMEs))):
			h.Lifecycle = "changed"
		default:
			h.Lifecycle = "active"
		}

		a := appear[h.Hostname]
		if a == nil {
			continue
		}
		first, lastT := a.first, a.last
		h.Evidence = append(h.Evidence, models.SourceEvidence{Source: "reconx", Reliability: models.ReliabilityHigh, FirstSeen: &first, LastSeen: &lastT})
		if h.FirstSeen == nil || first.Before(*h.FirstSeen) {
			h.FirstSeen = &first
		}
		current := map[string]bool{}
		for _, ip := range h.IPs {
			current[ip] = true
		}
		for ip, w := range a.ips {
			f, l := w[0], w[1]
			if current[ip] {
				for k := range h.History {
					if h.History[k].Value == ip && (h.History[k].FirstSeen == nil || f.Before(*h.History[k].FirstSeen)) {
						h.History[k].FirstSeen = &f
					}
				}
				continue
			}
			found := false
			for k := range h.History {
				if h.History[k].Value == ip {
					found = true
					if h.History[k].LastSeen == nil || l.After(*h.History[k].LastSeen) {
						h.History[k].LastSeen = &l
					}
				}
			}
			if !found {
				typ := "A"
				if strings.Contains(ip, ":") {
					typ = "AAAA"
				}
				h.History = append(h.History, models.HistoricalValue{Type: typ, Value: ip, Source: "reconx", FirstSeen: &f, LastSeen: &l})
			}
		}
	}
}

// Compare diffs two saved reports (older first) for the scan-comparison view.
func Compare(a, b *models.ScanReport, fileA, fileB string) *models.ChangeSet {
	if b.Timestamp.Before(a.Timestamp) {
		a, b = b, a
		fileA, fileB = fileB, fileA
	}
	return Diff(FromReport(a, fileA), FromReport(b, fileB))
}

// ── helpers ──────────────────────────────────────────────────────────────────

func ipSet(s Snapshot) map[string]bool {
	out := map[string]bool{}
	for _, h := range s.Hosts {
		for _, ip := range h.IPs {
			out[ip] = true
		}
	}
	return out
}

func certLabel(c models.CertInfo) string {
	name := c.CommonName
	if name == "" && len(c.SANs) > 0 {
		name = c.SANs[0]
	}
	return name + " (crt.sh #" + strconv.FormatInt(c.ID, 10) + ")"
}

func sorted(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func j(s []string) string { return strings.Join(s, ", ") }

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func firstNonEmpty(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}
