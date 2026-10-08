package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"reconx/pkg/models"
)

func TestParseDuration(t *testing.T) {
	for in, want := range map[string]time.Duration{"6h": 6 * time.Hour, "1d": 24 * time.Hour, "1.5d": 36 * time.Hour, "2w": 14 * 24 * time.Hour, "90m": 90 * time.Minute} {
		got, err := ParseDuration(in)
		if err != nil || got != want {
			t.Errorf("ParseDuration(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "x", "-1d", "0d"} {
		if _, err := ParseDuration(bad); err == nil {
			t.Errorf("ParseDuration(%q) accepted", bad)
		}
	}
	for d, want := range map[time.Duration]string{24 * time.Hour: "1d", 7 * 24 * time.Hour: "1w", 6 * time.Hour: "6h", 90 * time.Minute: "1h30m"} {
		if got := HumanDuration(d); got != want {
			t.Errorf("HumanDuration(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestStoreLifecycle(t *testing.T) {
	s := OpenStore(t.TempDir())
	if _, err := s.Add(Monitor{Target: "x.com", Interval: Duration(10 * time.Minute)}); err == nil {
		t.Error("interval below minimum accepted")
	}
	if _, err := s.Add(Monitor{Target: "x.com", Interval: Duration(time.Hour), Rules: []string{"bogus"}}); err == nil {
		t.Error("unknown rule accepted")
	}
	if _, err := s.Add(Monitor{Target: "x.com", Interval: Duration(time.Hour), Webhook: "ftp://h"}); err == nil {
		t.Error("non-http webhook accepted")
	}
	m, err := s.Add(Monitor{Target: " Example.COM ", Interval: Duration(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if m.Target != "example.com" || !m.Enabled || m.MinSeverity != SevLow || !m.Due(time.Now()) {
		t.Errorf("new monitor = %+v", m)
	}
	if _, err := s.Add(Monitor{Target: "example.com", Interval: Duration(24 * time.Hour)}); err == nil {
		t.Error("duplicate target accepted")
	}
	if got, err := s.Find("example.com"); err != nil || got.ID != m.ID {
		t.Errorf("Find by target = %v, %v", got, err)
	}
	if _, err := s.Update(m.ID, func(x *Monitor) error { x.Enabled = false; return nil }); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Find(m.ID); got.Enabled || got.Due(time.Now()) {
		t.Error("paused monitor still due")
	}
	// Interval round-trips through JSON as a duration string.
	got, _ := s.Find(m.ID)
	if time.Duration(got.Interval) != 24*time.Hour {
		t.Errorf("interval after reload = %v", time.Duration(got.Interval))
	}
	if err := s.Remove(m.ID); err != nil {
		t.Fatal(err)
	}
	if ms, _ := s.List(); len(ms) != 0 {
		t.Errorf("monitors after remove = %d", len(ms))
	}
}

func TestAlertLog(t *testing.T) {
	s := OpenStore(t.TempDir())
	if a, err := s.Alerts("", 0); err != nil || len(a) != 0 {
		t.Fatalf("empty log = %v, %v", a, err)
	}
	s.AppendAlerts([]Alert{{ID: "1", Target: "a.com", Title: "one"}, {ID: "2", Target: "b.com", Title: "two"}})
	s.AppendAlerts([]Alert{{ID: "3", Target: "a.com", Title: "three"}})
	all, _ := s.Alerts("", 0)
	if len(all) != 3 || all[0].ID != "3" {
		t.Errorf("alerts newest-first = %+v", all)
	}
	a, _ := s.Alerts("A.com", 1)
	if len(a) != 1 || a[0].ID != "3" {
		t.Errorf("filtered/limited = %+v", a)
	}
}

func rep(mut func(pi *models.PassiveIntel)) *models.ScanReport {
	r := &models.ScanReport{
		Target:    &models.Target{Value: "example.com", Type: models.TargetTypeDomain},
		Timestamp: time.Now().Add(-time.Hour),
		Intel: &models.PassiveIntel{
			Hosts:        []models.HostIntel{{Hostname: "www.example.com", DNSStatus: "resolves", IPs: []string{"1.1.1.1"}}},
			IPs:          []models.IPInfo{{IP: "1.1.1.1", Hostnames: []string{"www.example.com"}, Exposure: &models.IPExposure{Ports: []int{443}}}},
			Email:        &models.EmailSecurity{SPF: models.SPFInfo{Present: true}, DMARC: models.DMARCInfo{Present: true, Policy: "reject"}, Score: 70, MaxScore: 80},
			Certificates: []models.CertInfo{{ID: 9, CommonName: "www.example.com", ExpiryStatus: "lt30", NotAfter: time.Now().Add(20 * 24 * time.Hour)}},
		},
	}
	if mut != nil {
		mut(r.Intel)
	}
	return r
}

func byRule(alerts []Alert) map[string]Alert {
	m := map[string]Alert{}
	for _, a := range alerts {
		m[a.Rule] = a
	}
	return m
}

func TestEvaluateBaseline(t *testing.T) {
	m := &Monitor{ID: "m1", Target: "example.com"}
	a := Evaluate(m, nil, rep(nil), "", "cur.json")
	if len(a) != 1 || a[0].Rule != "baseline" || a[0].Severity != SevInfo {
		t.Errorf("baseline alerts = %+v", a)
	}
}

func TestEvaluateNoChange(t *testing.T) {
	m := &Monitor{ID: "m1", Target: "example.com"}
	prev, cur := rep(nil), rep(nil)
	cur.Timestamp = time.Now()
	if a := Evaluate(m, prev, cur, "p.json", "c.json"); len(a) != 0 {
		t.Errorf("unchanged scan raised %+v", a)
	}
}

func TestEvaluateChanges(t *testing.T) {
	m := &Monitor{ID: "m1", Target: "example.com"}
	prev := rep(nil)
	cur := rep(func(pi *models.PassiveIntel) {
		pi.Hosts[0].IPs = []string{"2.2.2.2"}
		pi.Hosts = append(pi.Hosts, models.HostIntel{Hostname: "admin.example.com", DNSStatus: "resolves", IPs: []string{"3.3.3.3"}, Interest: "high"})
		pi.IPs = []models.IPInfo{
			{IP: "1.1.1.1", Hostnames: []string{"www.example.com"}, Exposure: &models.IPExposure{Ports: []int{443, 22}, Vulns: []models.CVERef{{ID: "CVE-2024-1", KEV: true}}}},
			// A provider's nameserver IP: exposure there is not the target's.
			{IP: "9.9.9.9", Hostnames: []string{"ns1.dnsprovider.net"}, Exposure: &models.IPExposure{Ports: []int{53, 80}}},
		}
		pi.Dangling = []models.DanglingIndicator{{Hostname: "old.example.com", CNAME: "gone.azurewebsites.net", Reason: "NXDOMAIN"}}
		pi.Email.DMARC.Policy = "none"
		pi.Email.Score = 40
		pi.Certificates[0].ExpiryStatus = "lt7"
		pi.Certificates[0].NotAfter = time.Now().Add(5 * 24 * time.Hour)
	})
	cur.Timestamp = time.Now()

	got := byRule(Evaluate(m, prev, cur, "p.json", "c.json"))
	if a := got[RuleSubdomainAdded]; a.Severity != SevHigh || len(a.Items) != 1 || !strings.Contains(a.Items[0], "high interest") {
		t.Errorf("subdomain alert = %+v", a)
	}
	if a := got[RuleDNSChanged]; a.Severity != SevMedium || len(a.Items) == 0 {
		t.Errorf("dns alert = %+v", a)
	}
	if a := got[RuleExposure]; a.Severity != SevHigh || len(a.Items) != 2 {
		t.Errorf("exposure alert = %+v", a)
	}
	if a := got[RuleDangling]; a.Severity != SevHigh || len(a.Items) != 1 {
		t.Errorf("dangling alert = %+v", a)
	}
	if a := got[RuleEmailPosture]; len(a.Items) != 2 {
		t.Errorf("email alert = %+v", a)
	}
	if a := got[RuleCertExpiring]; a.Severity != SevHigh || len(a.Items) != 1 {
		t.Errorf("cert alert = %+v", a)
	}
	all := Evaluate(m, prev, cur, "p.json", "c.json")
	if all[0].Severity != SevHigh {
		t.Error("alerts not ordered by severity")
	}

	// Rule filtering and once-per-threshold certificate alerts.
	m.Rules = []string{RuleCertExpiring}
	if a := Evaluate(m, cur, cur, "c.json", "c.json"); len(a) != 0 {
		t.Errorf("cert already past threshold re-alerted: %+v", a)
	}
	if a := Evaluate(m, prev, cur, "p.json", "c.json"); len(a) != 1 || a[0].Rule != RuleCertExpiring {
		t.Errorf("rule filter = %+v", a)
	}
}

func TestWebhookKindsAndSend(t *testing.T) {
	for in, want := range map[string]string{
		"https://hooks.slack.com/services/T/B/X":      "slack",
		"https://discord.com/api/webhooks/1/abc":      "discord",
		"https://acme.webhook.office.com/webhookb2/x": "teams",
		"https://ntfy.example.org/reconx":             "generic",
	} {
		if got := WebhookKind(in); got != want {
			t.Errorf("WebhookKind(%q) = %q, want %q", in, got, want)
		}
	}
	if got := MaskWebhook("https://hooks.slack.com/services/T/B/SECRET"); strings.Contains(got, "SECRET") {
		t.Errorf("MaskWebhook leaks: %q", got)
	}

	var mu sync.Mutex
	var bodies []map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var v map[string]interface{}
		json.Unmarshal(b, &v)
		mu.Lock()
		bodies = append(bodies, v)
		mu.Unlock()
		if strings.Contains(string(b), "fail-me") {
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	m := &Monitor{Target: "example.com", Webhook: srv.URL, MinSeverity: SevMedium}
	alerts := []Alert{
		{Severity: SevHigh, Title: "big"},
		{Severity: SevLow, Title: "small"},
		{Severity: SevMedium, Title: "fail-me"},
	}
	(&Notifier{}).Send(context.Background(), m, alerts)
	if alerts[0].Delivered != "sent" || !strings.HasPrefix(alerts[1].Delivered, "skipped") || !strings.HasPrefix(alerts[2].Delivered, "failed: HTTP 400") {
		t.Errorf("delivery = %q / %q / %q", alerts[0].Delivered, alerts[1].Delivered, alerts[2].Delivered)
	}
	if len(bodies) != 2 || bodies[0]["alert"] == nil || !strings.Contains(bodies[0]["text"].(string), "[ReconX HIGH] big") {
		t.Errorf("generic payloads = %+v", bodies)
	}
	if err := (&Notifier{}).Test(context.Background(), m); err != nil {
		t.Errorf("test webhook: %v", err)
	}
}

func TestRunner(t *testing.T) {
	s := OpenStore(t.TempDir())
	m, _ := s.Add(Monitor{Target: "example.com", Interval: Duration(6 * time.Hour)})
	m2, _ := s.Add(Monitor{Target: "paused.com", Interval: Duration(6 * time.Hour)})
	s.Update(m2.ID, func(x *Monitor) error { x.Enabled = false; return nil })

	var saved []*models.ScanReport
	runs := 0
	r := &Runner{
		Store: s,
		Scan: func(ctx context.Context, mon *Monitor) (*models.ScanReport, string, error) {
			runs++
			if runs == 3 {
				return nil, "", errors.New("boom")
			}
			cur := rep(nil)
			cur.Timestamp = time.Now()
			if runs == 2 {
				cur.Intel.Hosts = append(cur.Intel.Hosts, models.HostIntel{Hostname: "new.example.com", DNSStatus: "resolves"})
			}
			saved = append(saved, cur)
			return cur, "scan.json", nil
		},
		Previous: func(target string) (*models.ScanReport, string) {
			if len(saved) == 0 {
				return nil, ""
			}
			return saved[len(saved)-1], "prev.json"
		},
	}

	if n := r.RunDue(context.Background(), time.Now()); n != 1 {
		t.Fatalf("RunDue ran %d monitors, want 1 (paused one skipped)", n)
	}
	got, _ := s.Find(m.ID)
	if got.LastStatus != "ok" || got.Runs != 1 || got.LastFile != "scan.json" || got.Due(time.Now()) {
		t.Errorf("after first run = %+v", got)
	}
	if n := r.RunDue(context.Background(), time.Now()); n != 0 {
		t.Errorf("monitor re-ran before its interval")
	}

	alerts, err := r.RunOne(context.Background(), m.ID)
	if err != nil || len(alerts) != 1 || alerts[0].Rule != RuleSubdomainAdded {
		t.Fatalf("second run alerts = %+v, %v", alerts, err)
	}
	if logged, _ := s.Alerts("example.com", 0); len(logged) != 2 {
		t.Errorf("logged alerts = %d, want 2 (baseline + subdomain)", len(logged))
	}

	if _, err := r.RunOne(context.Background(), m.ID); err == nil {
		t.Error("scan failure not reported")
	}
	if got, _ := s.Find(m.ID); got.LastStatus != "error" || got.LastError != "boom" {
		t.Errorf("after failure = %+v", got)
	}

	s.Update(m.ID, func(x *Monitor) error { x.LastStatus = "running"; return nil })
	r.RecoverInterrupted()
	if got, _ := s.Find(m.ID); got.LastStatus != "error" || !got.Due(time.Now()) {
		t.Errorf("interrupted monitor not recovered: %+v", got)
	}
}
