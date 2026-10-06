package history

import (
	"testing"
	"time"

	rdns "reconx/internal/dns"
	"reconx/pkg/models"
)

func report(ts time.Time, hosts map[string][]string, mx string) *models.ScanReport {
	pi := &models.PassiveIntel{}
	for h, ips := range hosts {
		st := "nxdomain"
		if len(ips) > 0 {
			st = "resolves"
		}
		pi.Hosts = append(pi.Hosts, models.HostIntel{Hostname: h, IPs: ips, DNSStatus: st})
	}
	return &models.ScanReport{
		Target:    &models.Target{Value: "example.com", Type: models.TargetTypeDomain},
		Timestamp: ts,
		DNS:       &rdns.Result{Records: []rdns.Record{{Type: "MX", Name: "example.com", Value: mx}}},
		Intel:     pi,
	}
}

func TestDiffAndApply(t *testing.T) {
	t0 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.AddDate(0, 0, 30)
	prev := report(t0, map[string][]string{
		"www.example.com": {"203.0.113.1"},
		"api.example.com": {"203.0.113.2"},
		"old.example.com": {"203.0.113.9"},
	}, "10 mx1.example.com")
	cur := report(t1, map[string][]string{
		"www.example.com": {"203.0.113.1"},
		"api.example.com": {"198.51.100.7"},
		"new.example.com": {"203.0.113.5"},
	}, "10 aspmx.l.google.com")

	cs := Diff(FromReport(prev, "a.json"), FromReport(cur, ""))
	s := cs.Summary
	if s.SubdomainsAdded != 1 || s.SubdomainsRemoved != 1 || s.HostsChanged != 1 || s.Unchanged != 1 {
		t.Errorf("host summary: %+v", s)
	}
	if s.IPsAdded != 2 || s.IPsRemoved != 2 || s.DNSChanges != 1 {
		t.Errorf("ip/dns summary: %+v", s)
	}

	Apply(cur, []Scan{{File: "a.json", Report: prev}})
	life := map[string]string{}
	for _, h := range cur.Intel.Hosts {
		life[h.Hostname] = h.Lifecycle
	}
	if life["new.example.com"] != "new" || life["api.example.com"] != "changed" || life["www.example.com"] != "active" {
		t.Errorf("lifecycle: %v", life)
	}
	for _, h := range cur.Intel.Hosts {
		if h.Hostname != "api.example.com" {
			continue
		}
		found := false
		for _, hv := range h.History {
			if hv.Value == "203.0.113.2" && !hv.Current && hv.Source == "reconx" {
				found = true
			}
		}
		if !found {
			t.Errorf("previous IP should appear as historical: %+v", h.History)
		}
		if h.FirstSeen == nil || !h.FirstSeen.Equal(t0) {
			t.Errorf("first seen should come from the earliest scan: %v", h.FirstSeen)
		}
	}
}

func TestTXTNormalizationIgnoresLegacySpacing(t *testing.T) {
	if normalizeDNS("TXT", "v=spf1 include:a.com -all") != normalizeDNS("TXT", "v=spf1 include:a.com  -all") {
		t.Errorf("TXT values differing only in whitespace should compare equal")
	}
}
