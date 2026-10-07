package intel

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"reconx/pkg/models"
)

const log4shell = `{"cve_id":"CVE-2021-44228","summary":"Apache Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints.","cvss":10.0,"cvss_version":3.0,"epss":0.99999,"ranking_epss":1.0,"kev":true,"ransomware_campaign":"Known","published_time":"2021-12-10T10:15:09"}`
const oldXSS = `{"cve_id":"CVE-2009-0796","summary":"XSS in Apache::Status.","cvss":2.6,"cvss_version":2.0,"cvss_v3":null,"epss":0.29638,"ranking_epss":0.98146,"kev":false,"ransomware_campaign":null,"published_time":"2009-04-07T23:30:00"}`

// testCVEDB points a client at a fresh mock server. Each test uses a unique
// path prefix so the process-wide cache never leaks between tests.
func testCVEDB(t *testing.T, handler http.HandlerFunc) *CVEDB {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c := NewCVEDB(5 * time.Second)
	c.baseURL = srv.URL + "/" + t.Name() + "/cve/"
	return c
}

func cveHandler(hits *int32) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		switch id {
		case "CVE-2021-44228":
			_, _ = w.Write([]byte(log4shell))
		case "CVE-2009-0796":
			_, _ = w.Write([]byte(oldXSS))
		case "CVE-2000-0001":
			_, _ = w.Write([]byte(`{"cve_id":`)) // malformed
		case "CVE-2000-0002":
			w.WriteHeader(http.StatusBadRequest)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"detail":"No information available"}`))
		}
	}
}

func TestCVEDBLookupParsesKEVAndEPSS(t *testing.T) {
	var hits int32
	c := testCVEDB(t, cveHandler(&hits))

	ref, err := c.Lookup(context.Background(), "cve-2021-44228")
	if err != nil || ref == nil {
		t.Fatalf("Lookup: %v / %v", ref, err)
	}
	if !ref.Enriched || !ref.KEV || ref.Ransomware != "Known" || ref.EPSS != 0.99999 || ref.EPSSPercentile != 1.0 || ref.CVSS != 10 || ref.Published != "2021-12-10" {
		t.Errorf("unexpected record: %+v", ref)
	}

	ref, _ = c.Lookup(context.Background(), "CVE-2009-0796")
	if ref.KEV || ref.Ransomware != "" || ref.CVSSVersion != 2 {
		t.Errorf("null fields not handled: %+v", ref)
	}

	// Cached: a second lookup of the same ID makes no request.
	before := atomic.LoadInt32(&hits)
	_, _ = c.Lookup(context.Background(), "CVE-2021-44228")
	if atomic.LoadInt32(&hits) != before {
		t.Error("repeat lookup was not served from cache")
	}
}

func TestCVEDBBatchDegradesGracefully(t *testing.T) {
	var hits int32
	c := testCVEDB(t, cveHandler(&hits))

	ids := []string{"CVE-2021-44228", "CVE-2021-44228", "CVE-2009-0796", "CVE-1999-9999", "CVE-2000-0001", "CVE-2000-0002"}
	got, err := c.LookupBatch(context.Background(), ids)
	if err == nil || !strings.Contains(err.Error(), "2 lookup(s) failed") {
		t.Errorf("expected 2 failures summarised, got %v", err)
	}
	if len(got) != 2 || got["CVE-2021-44228"] == nil || got["CVE-2009-0796"] == nil {
		t.Errorf("expected the two known CVEs, got %v", got)
	}
	if hits != 5 {
		t.Errorf("expected 5 requests (duplicate collapsed), got %d", hits)
	}
}

func TestCVEDBBatchCap(t *testing.T) {
	var hits int32
	c := testCVEDB(t, cveHandler(&hits))
	ids := make([]string, maxCVELookups+7)
	for i := range ids {
		ids[i] = fmt.Sprintf("CVE-2030-%05d", i)
	}
	_, err := c.LookupBatch(context.Background(), ids)
	if err == nil || !strings.Contains(err.Error(), "7 CVE(s) over the") {
		t.Errorf("expected cap note, got %v", err)
	}
	if int(hits) != maxCVELookups {
		t.Errorf("expected %d requests, got %d", maxCVELookups, hits)
	}
}

func TestApplyCVEDetailsOrdersForTriage(t *testing.T) {
	ips := []models.IPInfo{{IP: "93.184.216.34", Exposure: &models.IPExposure{Vulns: []models.CVERef{
		{ID: "CVE-2009-0796"}, {ID: "CVE-2018-0001"}, {ID: "CVE-2021-44228"},
	}}}, {IP: "93.184.216.35"}}
	details := map[string]*models.CVERef{
		"CVE-2021-44228": {ID: "CVE-2021-44228", Enriched: true, KEV: true, EPSS: 0.9},
		"CVE-2009-0796":  {ID: "CVE-2009-0796", Enriched: true, EPSS: 0.3},
	}
	ApplyCVEDetails(ips, details)
	v := ips[0].Exposure.Vulns
	if v[0].ID != "CVE-2021-44228" || v[1].ID != "CVE-2009-0796" || v[2].ID != "CVE-2018-0001" {
		t.Errorf("wrong triage order: %v", v)
	}
	if v[2].Enriched {
		t.Error("CVE without a CVEDB record marked enriched")
	}
}

func TestKEVRaisesHostInterest(t *testing.T) {
	h := &models.HostIntel{Hostname: "www.example.com", IPs: []string{"93.184.216.34"}, InterestScore: 1, Interest: "low"}
	AddExposureInterest(h, map[string][]string{"93.184.216.34": {"CVE-2021-44228"}})
	if h.InterestScore != 3 || h.Interest != "medium" || !strings.Contains(h.InterestFactors[0], "CVE-2021-44228") {
		t.Errorf("unexpected interest: %d %s %v", h.InterestScore, h.Interest, h.InterestFactors)
	}

	other := &models.HostIntel{IPs: []string{"93.184.216.99"}, InterestScore: 1, Interest: "low"}
	AddExposureInterest(other, map[string][]string{"93.184.216.34": {"CVE-2021-44228"}})
	if other.InterestScore != 1 || len(other.InterestFactors) != 0 {
		t.Error("host on an unaffected IP was changed")
	}
}
