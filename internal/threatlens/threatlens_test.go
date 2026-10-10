package threatlens

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"reconx/pkg/models"
)

// enrich_response.json is a real ThreatLens answer (2026-10-10) for a Feodo
// Tracker C2 IP, github.com, a Shodan scanner and a private address: the
// contract this client reads.
func fixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/enrich_response.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func server(t *testing.T, handler http.HandlerFunc) (*httptest.Server, Config) {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts, Config{URL: ts.URL, Key: "tl_test"}
}

func TestEnrichReadsTheContract(t *testing.T) {
	var got enrichIn
	_, cfg := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/enrich" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("X-API-Key") != "tl_test" {
			t.Errorf("missing API key header")
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write(fixture(t))
	})
	ti := New(cfg).Enrich(context.Background(), []string{"162.243.103.246", "GitHub.com ", "github.com", "71.6.199.23", "10.0.0.5"})
	if got.TLP != "TLP:GREEN" {
		t.Errorf("default TLP = %q, want TLP:GREEN", got.TLP)
	}
	if len(got.Indicators) != 4 { // trimmed, lower-cased, deduplicated
		t.Errorf("sent %v", got.Indicators)
	}
	if ti.Status != "ok" && ti.Status != "partial" {
		t.Fatalf("status %q: %s", ti.Status, ti.Error)
	}
	if len(ti.Items) != 3 || ti.Counts["malicious"] != 1 || ti.Counts["benign"] != 1 {
		t.Fatalf("items %d counts %v", len(ti.Items), ti.Counts)
	}
	top := ti.Items[0] // worst first
	if top.Value != "162.243.103.246" || top.Verdict != "malicious" || top.Action != "block" || top.Score < 70 {
		t.Errorf("top verdict %+v", top)
	}
	if top.Defanged != "162[.]243[.]103[.]246" || len(top.KnownSources) == 0 || top.KnownSources[0] != "feodo" {
		t.Errorf("defanged %q known %v", top.Defanged, top.KnownSources)
	}
	if len(top.Related) == 0 || !strings.Contains(top.Related[0], "Emotet") {
		t.Errorf("related %v", top.Related)
	}
	if len(ti.Rejected) != 1 || ti.Rejected[0].Value != "10.0.0.5" {
		t.Errorf("rejected %v", ti.Rejected)
	}
	if ti.Items[len(ti.Items)-1].Verdict != "benign" {
		t.Errorf("benign should sort last: %+v", ti.Items)
	}
	if f := Flagged(ti); len(f) != 1 || f[0].Value != "162.243.103.246" {
		t.Errorf("flagged %v", f)
	}
}

func TestEnrichBatchesAndKeepsPartialResults(t *testing.T) {
	var calls atomic.Int32
	_, cfg := server(t, func(w http.ResponseWriter, r *http.Request) {
		var in enrichIn
		_ = json.NewDecoder(r.Body).Decode(&in)
		if len(in.Indicators) > BatchSize {
			t.Errorf("batch of %d", len(in.Indicators))
		}
		if calls.Add(1) == 2 {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(fixture(t))
	})
	values := make([]string, 0, 250) // 250 distinct names: three batches of at most 100
	for i := 0; i < 250; i++ {
		values = append(values, strings.ToLower(string(rune('a'+i%26)))+strings.Repeat("y", i/26)+".example.com")
	}
	ti := New(cfg).Enrich(context.Background(), values)
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want 2 (stop after the failing batch)", calls.Load())
	}
	if ti.Status != "partial" || !strings.Contains(ti.Error, "HTTP 500") || len(ti.Items) != 3 {
		t.Fatalf("status %q error %q items %d", ti.Status, ti.Error, len(ti.Items))
	}
}

func TestEnrichExplainsServerRefusals(t *testing.T) {
	for code, want := range map[int]string{
		http.StatusUnauthorized:    "rejected the API key",
		http.StatusForbidden:       "analyst role",
		http.StatusTooManyRequests: "rate limit",
	} {
		_, cfg := server(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) })
		ti := New(cfg).Enrich(context.Background(), []string{"example.com"})
		if ti.Status != "error" || !strings.Contains(ti.Error, want) {
			t.Errorf("%d: status %q error %q", code, ti.Status, ti.Error)
		}
	}
	ti := New(Config{URL: "http://127.0.0.1:1", Key: "k"}).Enrich(context.Background(), []string{"example.com"})
	if ti.Status != "error" || !strings.Contains(ti.Error, "unreachable") {
		t.Errorf("unreachable: %q", ti.Error)
	}
}

func TestConfig(t *testing.T) {
	t.Setenv(EnvURL, "http://tl.internal:8000")
	t.Setenv(EnvKey, "tl_env")
	c := Config{}.FromEnv()
	if c.URL != "http://tl.internal:8000" || c.Key != "tl_env" || c.Validate() != nil {
		t.Errorf("from env: %+v %v", c, c.Validate())
	}
	if c := (Config{URL: "http://flag:1"}).FromEnv(); c.URL != "http://flag:1" {
		t.Errorf("flag must win over env: %q", c.URL)
	}
	t.Setenv(EnvKey, "")
	if err := (Config{URL: "http://x"}).FromEnv().Validate(); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("missing key: %v", err)
	}
	for _, bad := range []Config{
		{URL: "ftp://x", Key: "k"}, {URL: "javascript:alert(1)", Key: "k"}, {URL: "http://", Key: "k"},
		{URL: "http://x", Key: "k", TLP: "TLP:WHITE"},
	} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestValuesPicksTargetResolvingHostsAndIPs(t *testing.T) {
	r := &models.ScanReport{
		Target: &models.Target{Value: "example.com", Type: models.TargetTypeDomain},
		Intel: &models.PassiveIntel{
			Hosts: []models.HostIntel{
				{Hostname: "www.example.com", DNSStatus: "resolves"},
				{Hostname: "old.example.com", DNSStatus: "nxdomain"},
				{Hostname: "EXAMPLE.com", DNSStatus: "resolves"},
			},
			IPs: []models.IPInfo{{IP: "93.184.216.34"}},
		},
	}
	got := strings.Join(Values(r), ",")
	if got != "example.com,www.example.com,93.184.216.34" {
		t.Errorf("values = %s", got)
	}
	ip := &models.ScanReport{Target: &models.Target{Value: "93.184.216.34", Type: models.TargetTypeIPv4}}
	if got := Values(ip); len(got) != 1 {
		t.Errorf("IP target: %v", got)
	}
	if got := Values(&models.ScanReport{Target: &models.Target{Value: "Acme", Type: models.TargetTypeOrg}}); len(got) != 0 {
		t.Errorf("org target: %v", got)
	}
}

func TestImportAssetsSendsTheReport(t *testing.T) {
	var got map[string]any
	_, cfg := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/assets/import/reconx" {
			t.Errorf("path %s", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"import_id":7,"duplicate":false,"hosts":3,"ips":2,"products":4,"new_assets":5,"updated_assets":0,"rejected":[{"value":"10.0.0.5","reason":"non-public"}]}`))
	})
	rep := &models.ScanReport{Target: &models.Target{Value: "example.com", Type: models.TargetTypeDomain}}
	res, err := New(cfg).ImportAssets(context.Background(), rep)
	if err != nil {
		t.Fatal(err)
	}
	if res.ImportID != 7 || res.NewAssets != 5 || len(res.Rejected) != 1 {
		t.Errorf("result %+v", res)
	}
	if got["target"].(map[string]any)["value"] != "example.com" {
		t.Errorf("sent %v", got)
	}
	_, deny := server(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) })
	if _, err := New(deny).ImportAssets(context.Background(), rep); err == nil || !strings.Contains(err.Error(), "analyst") {
		t.Errorf("403: %v", err)
	}
}
