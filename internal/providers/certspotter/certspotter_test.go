package certspotter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"reconx/pkg/models"
)

const page1 = `[
 {"id":"1","dns_names":["example.com","www.example.com"],"not_before":"2024-01-01T00:00:00Z","not_after":"2024-04-01T00:00:00Z"},
 {"id":"2","dns_names":["*.API.example.com","other.org"],"not_before":"2025-06-01T00:00:00Z","not_after":"2025-09-01T00:00:00Z"}
]`
const page2 = `[
 {"id":"3","dns_names":["www.example.com","notexample.com"],"not_before":"2026-02-01T00:00:00Z","not_after":"2026-05-01T00:00:00Z"}
]`

// server mimics Cert Spotter: pages linked with the real API's /v1-less URLs.
func server(t *testing.T, calls *int32, after2 func(w http.ResponseWriter)) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(calls, 1)
		if r.URL.Path != "/v1/issuances" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		q := r.URL.Query()
		if q.Get("domain") != "example.com" || q.Get("include_subdomains") != "true" || q.Get("expand") != "dns_names" {
			t.Errorf("bad query %s", r.URL.RawQuery)
		}
		switch q.Get("after") {
		case "":
			w.Header().Set("Link", `<`+srv.URL+`/issuances?after=2&domain=example.com&expand=dns_names&include_subdomains=true>; rel="next"`)
			_, _ = w.Write([]byte(page1))
		case "2":
			after2(w)
		default:
			_, _ = w.Write([]byte(`[]`))
		}
	}))
	return srv
}

func provider(srv *httptest.Server, pages int) *Provider {
	p := NewProvider(5 * time.Second)
	p.baseURL = srv.URL + "/v1/issuances"
	p.apiKey = ""
	p.maxPages = pages
	return p
}

var target = models.Target{Value: "example.com", Type: models.TargetTypeDomain}

func TestCertSpotterCollectFollowsPagination(t *testing.T) {
	var calls int32
	srv := server(t, &calls, func(w http.ResponseWriter) {
		w.Header().Set("Link", `</issuances?after=3&domain=example.com&expand=dns_names&include_subdomains=true>; rel="next"`)
		_, _ = w.Write([]byte(page2))
	})
	defer srv.Close()

	results, err := provider(srv, 5).Collect(context.Background(), target)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := map[string]map[string]string{}
	for _, r := range results {
		if r.Source != "certspotter" || r.Type != models.AssetTypeSubdomain {
			t.Errorf("bad result: %+v", r)
		}
		got[r.Value] = r.Metadata
	}
	if len(got) != 3 || got["api.example.com"] == nil || got["example.com"] == nil {
		t.Fatalf("expected example.com, www and api (wildcard/case stripped, out-of-scope dropped), got %v", got)
	}
	if w := got["www.example.com"]; w["first_seen"] != "2024-01-01T00:00:00Z" || w["last_seen"] != "2026-02-01T00:00:00Z" {
		t.Errorf("www span not merged across pages: %v", w)
	}
	if calls != 3 {
		t.Errorf("expected 3 page requests (last one empty), got %d", calls)
	}
}

func TestCertSpotterPageCap(t *testing.T) {
	var calls int32
	srv := server(t, &calls, func(w http.ResponseWriter) { t.Error("page cap exceeded") })
	defer srv.Close()

	if _, err := provider(srv, 1).Collect(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("expected 1 request with maxPages=1, got %d", calls)
	}
}

func TestCertSpotterQuotaOnLaterPageKeepsResults(t *testing.T) {
	var calls int32
	srv := server(t, &calls, func(w http.ResponseWriter) {
		w.Header().Set("Retry-After", "3000")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	defer srv.Close()

	start := time.Now()
	results, err := provider(srv, 5).Collect(context.Background(), target)
	if err != nil || len(results) != 3 {
		t.Fatalf("expected page-1 hosts despite 429, got %d / %v", len(results), err)
	}
	if time.Since(start) > 2*time.Second {
		t.Error("a long Retry-After stalled the provider")
	}
}

func TestCertSpotterQuotaOnFirstPageIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "3000")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	_, err := provider(srv, 2).Collect(context.Background(), target)
	if err == nil || !strings.Contains(err.Error(), "quota") || !strings.Contains(err.Error(), APIKeyEnv) {
		t.Errorf("expected a quota error naming %s, got %v", APIKeyEnv, err)
	}
}

func TestCertSpotterMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"id":`))
	}))
	defer srv.Close()

	if _, err := provider(srv, 2).Collect(context.Background(), target); err == nil {
		t.Error("expected a decode error")
	}
}

func TestCertSpotterSendsAPIKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer k123" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	p := provider(srv, 1)
	p.apiKey = "k123"
	if _, err := p.Collect(context.Background(), target); err != nil {
		t.Fatal(err)
	}
}
