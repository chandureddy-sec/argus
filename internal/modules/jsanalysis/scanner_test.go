package jsanalysis

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAnalyzeScripts_DetectsSecretAndSourceMap(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		// Contains an AWS-key-shaped string and a source map reference.
		_, _ = w.Write([]byte("var k='AKIAIOSFODNN7EXAMPLE';\n//# sourceMappingURL=app.js.map"))
	})
	mux.HandleFunc("/app.js.map", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"version":3}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	findings := AnalyzeScripts(ctx, []string{srv.URL + "/app.js"}, srv.URL)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]

	foundAWS := false
	for _, s := range f.Secrets {
		if strings.Contains(s, "AWS") {
			foundAWS = true
		}
	}
	if !foundAWS {
		t.Errorf("expected AWS key secret, got %v", f.Secrets)
	}
	if !f.SourceMapReachable {
		t.Errorf("expected source map to be reachable")
	}
}

func TestAnalyzeScripts_CleanScriptNoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("console.log('nothing to see here');"))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if findings := AnalyzeScripts(ctx, []string{srv.URL + "/clean.js"}, srv.URL); len(findings) != 0 {
		t.Errorf("clean script should produce no findings, got %+v", findings)
	}
}
