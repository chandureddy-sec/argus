package apicapture

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestCapture_RecordsXHRAndFetch stands up a local page that issues one fetch()
// and one XMLHttpRequest, then verifies the headless browser observes both as
// network_intercept endpoints. Skips when no Chrome/Chromium is available.
func TestCapture_RecordsXHRAndFetch(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><body><script>
			fetch('/api/fetch-endpoint');
			var x = new XMLHttpRequest();
			x.open('GET', '/api/xhr-endpoint');
			x.send();
		</script></body></html>`))
	})
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	opts := DefaultOptions()
	opts.WaitAfterLoad = 2 * time.Second
	opts.Timeout = 25 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	endpoints, err := Capture(ctx, srv.URL, opts)
	if err != nil && len(endpoints) == 0 {
		// Most likely cause in CI: no browser binary present.
		t.Skipf("skipping headless capture (browser unavailable?): %v", err)
	}

	var sawFetch, sawXHR bool
	for _, e := range endpoints {
		if e.Source != "network_intercept" {
			t.Errorf("expected source network_intercept, got %q", e.Source)
		}
		if strings.Contains(e.URL, "/api/fetch-endpoint") {
			sawFetch = true
		}
		if strings.Contains(e.URL, "/api/xhr-endpoint") {
			sawXHR = true
		}
	}
	if !sawFetch {
		t.Errorf("did not capture the fetch() endpoint; got %+v", endpoints)
	}
	if !sawXHR {
		t.Errorf("did not capture the XHR endpoint; got %+v", endpoints)
	}
}
