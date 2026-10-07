package urlscan

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

// Page 1: an in-scope scan, an older scan of the same host, a redirect from
// a third-party shortener into scope, and an out-of-scope scan.
const page1 = `{"results":[
 {"_id":"uuid-new","sort":[1791349560787,"uuid-new"],
  "task":{"domain":"www.example.com","url":"https://www.example.com/","time":"2026-10-06T10:00:00.000Z"},
  "page":{"domain":"www.example.com","url":"https://www.example.com/","title":"Example Home","server":"nginx","status":"200","ip":"93.184.216.34","asn":"AS15133","asnname":"EDGECAST, US","tlsIssuer":"DigiCert"},
  "screenshot":"https://urlscan.io/screenshots/uuid-new.png"},
 {"_id":"uuid-old","sort":[1691349560787,"uuid-old"],
  "task":{"domain":"www.example.com","url":"https://www.example.com/","time":"2025-01-01T00:00:00.000Z"},
  "page":{"domain":"www.example.com","title":"Old title","server":"apache"},
  "screenshot":"https://urlscan.io/screenshots/uuid-old.png"},
 {"_id":"uuid-redir","sort":[1691349560000,"uuid-redir"],
  "task":{"domain":"href.li","url":"https://href.li/?https://login.example.com","time":"2026-05-01T00:00:00.000Z"},
  "page":{"domain":"login.example.com","url":"https://login.example.com/","title":"Sign in"},
  "screenshot":"https://urlscan.io/screenshots/uuid-redir.png"},
 {"_id":"uuid-oos","sort":[1691340000000,"uuid-oos"],
  "task":{"domain":"evil-example.com","time":"2026-05-01T00:00:00.000Z"},
  "page":{"domain":"notexample.com"}}
],"total":5,"has_more":true}`

const page2 = `{"results":[
 {"_id":"uuid-api","sort":[1591340000000,"uuid-api"],
  "task":{"domain":"API.Example.com.","time":"2024-03-01T00:00:00.000Z"},
  "page":{"domain":"api.example.com","title":"API","status":"401"}}
],"total":5,"has_more":false}`

func newProvider(srv *httptest.Server) *Provider {
	p := NewProvider(5 * time.Second)
	p.baseURL = srv.URL + "/api/v1/"
	p.pageDelay, p.techDelay = 0, 0
	p.apiKey = ""
	return p
}

func TestURLScanCollect(t *testing.T) {
	var cursor atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if q := r.URL.Query().Get("q"); q != "domain:example.com" {
			t.Errorf("unexpected query %q", q)
		}
		if r.Header.Get("API-Key") != "" {
			t.Error("API key sent although none is configured")
		}
		if sa := r.URL.Query().Get("search_after"); sa != "" {
			cursor.Store(sa)
			_, _ = w.Write([]byte(page2))
			return
		}
		_, _ = w.Write([]byte(page1))
	}))
	defer srv.Close()

	results, err := newProvider(srv).Collect(context.Background(), models.Target{Value: "example.com", Type: models.TargetTypeDomain})
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	if got, _ := cursor.Load().(string); got != "1691340000000,uuid-oos" {
		t.Errorf("search_after cursor = %q", got)
	}

	byHost := map[string]models.RawResult{}
	for _, r := range results {
		if r.Source != "urlscan" || r.Type != models.AssetTypeSubdomain {
			t.Errorf("bad result shape: %+v", r)
		}
		byHost[r.Value] = r
	}
	if len(byHost) != 3 {
		t.Fatalf("expected www, login and api in scope, got %v", byHost)
	}

	www := byHost["www.example.com"].Metadata
	if www["title"] != "Example Home" || www["server"] != "nginx" || www["screenshot"] != "https://urlscan.io/screenshots/uuid-new.png" ||
		www["scan_url"] != "https://urlscan.io/result/uuid-new/" || www["scans"] != "2" || www["asn"] != "AS15133 EDGECAST, US" {
		t.Errorf("www should carry the newest scan's details: %v", www)
	}
	if !strings.HasPrefix(www["first_seen"], "2025-01-01") || !strings.HasPrefix(www["last_seen"], "2026-10-06") {
		t.Errorf("observation window wrong: %s .. %s", www["first_seen"], www["last_seen"])
	}
	if byHost["login.example.com"].Metadata["title"] != "Sign in" {
		t.Error("redirect target host lost its page details")
	}
	if _, ok := byHost["api.example.com"]; !ok {
		t.Error("host name not normalised (case / trailing dot)")
	}
}

func TestURLScanRateLimitedFirstPageIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Rate-Limit-Reset-After", "42")
		w.WriteHeader(http.StatusForbidden) // non-retryable, keeps the test fast
	}))
	defer srv.Close()

	_, err := newProvider(srv).Collect(context.Background(), models.Target{Value: "example.com", Type: models.TargetTypeDomain})
	if err == nil {
		t.Fatal("expected an error when search fails outright")
	}
}

func TestURLScanLaterPageFailureKeepsResults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("search_after") != "" {
			_, _ = w.Write([]byte(`{"results":[`)) // malformed second page
			return
		}
		_, _ = w.Write([]byte(page1))
	}))
	defer srv.Close()

	results, err := newProvider(srv).Collect(context.Background(), models.Target{Value: "example.com", Type: models.TargetTypeDomain})
	if err != nil || len(results) != 2 {
		t.Fatalf("expected page-1 results despite page-2 failure, got %d / %v", len(results), err)
	}
}

func TestURLScanTechnologiesWithAPIKey(t *testing.T) {
	var resultCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("API-Key") != "test-key" {
			t.Errorf("API key header missing on %s", r.URL.Path)
		}
		if strings.Contains(r.URL.Path, "/result/") {
			atomic.AddInt32(&resultCalls, 1)
			if strings.Contains(r.URL.Path, "uuid-new") {
				_, _ = w.Write([]byte(`{"meta":{"processors":{"wappa":{"data":[{"app":"Nginx"},{"app":"React"},{"app":"Nginx"}]}}}}`))
				return
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(page2Only))
	}))
	defer srv.Close()

	p := newProvider(srv)
	p.apiKey = "test-key"
	results, err := p.Collect(context.Background(), models.Target{Value: "example.com", Type: models.TargetTypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	techs := map[string]string{}
	for _, r := range results {
		techs[r.Value] = r.Metadata["technologies"]
	}
	if techs["www.example.com"] != "Nginx, React" {
		t.Errorf("technologies = %q", techs["www.example.com"])
	}
	if techs["login.example.com"] != "" {
		t.Error("failed result lookup should leave technologies empty")
	}
	if resultCalls != 2 {
		t.Errorf("expected one result call per host with a scan, got %d", resultCalls)
	}
}

// page2Only is page 1 without pagination, for the keyed test.
var page2Only = strings.Replace(page1, `"has_more":true`, `"has_more":false`, 1)

func TestURLScanUnsupportedTarget(t *testing.T) {
	_, err := NewProvider(time.Second).Collect(context.Background(), models.Target{Value: "1.2.3.4", Type: models.TargetTypeIPv4})
	if err == nil {
		t.Error("expected an error for a non-domain target")
	}
}
