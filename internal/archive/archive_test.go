package archive

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTransportArchivesOnlyTaggedRequests(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/json" {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			io.WriteString(w, `{"ok":true}`)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, "<h1>hi</h1>")
	}))
	defer srv.Close()

	dir := filepath.Join(t.TempDir(), "raw", "scan1")
	a, err := New(dir, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &Transport{Base: http.DefaultTransport}}
	get := func(ctx context.Context, path string) string {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+path, nil)
		req.Header.Set("Authorization", "Bearer super-secret")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}

	ctx := WithArchive(context.Background(), a)
	if got := get(ctx, "/json?apikey=abc123&q=example.com"); got != `{"ok":true}` {
		t.Fatalf("provider saw %q", got)
	}
	if got := get(ctx, "/page"); got != "<h1>hi</h1>" {
		t.Fatalf("provider saw %q", got)
	}
	get(context.Background(), "/json") // untagged: not archived
	if a.Count() != 2 {
		t.Fatalf("archived %d responses, want 2", a.Count())
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	var m Manifest
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "abc123") || strings.Contains(string(data), "super-secret") {
		t.Error("manifest leaks a key")
	}
	e := m.Entries[0]
	if !strings.Contains(e.URL, "apikey=REDACTED") || !strings.Contains(e.URL, "q=example.com") {
		t.Errorf("url = %q", e.URL)
	}
	if e.Status != 200 || !strings.HasSuffix(e.File, ".json") || e.Bytes != 11 || len(e.SHA256) != 64 {
		t.Errorf("entry = %+v", e)
	}
	if !strings.HasSuffix(m.Entries[1].File, ".html") {
		t.Errorf("html entry file = %q", m.Entries[1].File)
	}
	body, err := os.ReadFile(filepath.Join(dir, e.File))
	if err != nil || string(body) != `{"ok":true}` {
		t.Errorf("stored body = %q, %v", body, err)
	}
}

func TestTransportRecordsErrors(t *testing.T) {
	a, _ := New(t.TempDir(), "x")
	client := &http.Client{Transport: &Transport{Base: http.DefaultTransport}}
	req, _ := http.NewRequestWithContext(WithArchive(context.Background(), a), http.MethodGet, "http://127.0.0.1:1/", nil)
	if _, err := client.Do(req); err == nil {
		t.Fatal("expected connection error")
	}
	a.Close()
	if a.Count() != 1 || a.entries[0].Error == "" {
		t.Errorf("entries = %+v", a.entries)
	}
}

func TestRedact(t *testing.T) {
	u, _ := url.Parse("https://user:pw@api.example.com/x?token=t&KEY=k&domain=a.com")
	got := Redact(u)
	if strings.Contains(got, "pw") || strings.Contains(got, "=t&") || strings.Contains(got, "KEY=k") || !strings.Contains(got, "domain=a.com") {
		t.Errorf("Redact = %q", got)
	}
}
