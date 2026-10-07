package intel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newInternetDBServer(t *testing.T, hits *int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		switch strings.TrimPrefix(r.URL.Path, "/") {
		case "93.184.216.34":
			_, _ = w.Write([]byte(`{"cpes":["cpe:/a:nginx:nginx:1.18.0"],"hostnames":["www.example.com"],"ip":"93.184.216.34","ports":[443,80,22],"tags":["cloud"],"vulns":["CVE-2021-23017","cve-2021-23017","CVE-2019-20372"]}`))
		case "93.184.216.35":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"detail":"No information available"}`))
		case "93.184.216.36":
			w.WriteHeader(http.StatusBadRequest)
		case "93.184.216.37":
			_, _ = w.Write([]byte(`{"ports":[80`))
		default:
			t.Errorf("unexpected lookup %s", r.URL.Path)
		}
	}))
}

func testInternetDB(url string) *InternetDB {
	d := NewInternetDB(5 * time.Second)
	d.baseURL = url + "/"
	return d
}

func TestInternetDBLookup(t *testing.T) {
	var hits int32
	srv := newInternetDBServer(t, &hits)
	defer srv.Close()

	exp, err := testInternetDB(srv.URL).Lookup(context.Background(), "93.184.216.34")
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if got := exp.Ports; len(got) != 3 || got[0] != 22 || got[2] != 443 {
		t.Errorf("ports not parsed/sorted: %v", got)
	}
	if len(exp.Vulns) != 2 || exp.Vulns[0].ID != "CVE-2019-20372" || exp.Vulns[1].ID != "CVE-2021-23017" {
		t.Errorf("vulns not normalised/deduped: %+v", exp.Vulns)
	}
	if len(exp.CPEs) != 1 || exp.Tags[0] != "cloud" || exp.Hostnames[0] != "www.example.com" {
		t.Errorf("unexpected exposure: %+v", exp)
	}
}

func TestInternetDBNotIndexedIsNotAnError(t *testing.T) {
	var hits int32
	srv := newInternetDBServer(t, &hits)
	defer srv.Close()

	exp, err := testInternetDB(srv.URL).Lookup(context.Background(), "93.184.216.35")
	if err != nil || exp != nil {
		t.Fatalf("404 should be (nil, nil), got (%+v, %v)", exp, err)
	}
}

func TestInternetDBBatchDegradesGracefully(t *testing.T) {
	var hits int32
	srv := newInternetDBServer(t, &hits)
	defer srv.Close()

	ips := []string{
		"93.184.216.34", "93.184.216.34", // duplicate: one request
		"93.184.216.35",                      // not indexed
		"93.184.216.36",                      // HTTP error
		"93.184.216.37",                      // malformed JSON
		"10.0.0.1", "127.0.0.1", "not-an-ip", // never sent
	}
	got, err := testInternetDB(srv.URL).LookupBatch(context.Background(), ips)
	if err == nil || !strings.Contains(err.Error(), "2 lookup(s) failed") {
		t.Errorf("expected a summary of 2 failures, got %v", err)
	}
	if len(got) != 1 || got["93.184.216.34"] == nil {
		t.Errorf("expected only the indexed IP in results, got %v", got)
	}
	if hits != 4 {
		t.Errorf("expected 4 requests (deduped, public only), got %d", hits)
	}
}

func TestInternetDBUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Close() // connection refused

	d := testInternetDB(srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	got, err := d.LookupBatch(ctx, []string{"93.184.216.34"})
	if err == nil || len(got) != 0 {
		t.Errorf("expected an error and no results, got %v / %v", got, err)
	}
}
