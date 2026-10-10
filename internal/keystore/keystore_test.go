package keystore

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSetGetStatusesAndApply(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "keys.json")
	s := Open(path)
	t.Setenv("RECONX_GITHUB_TOKEN", "")
	t.Setenv("RECONX_URLSCAN_API_KEY", "")
	t.Setenv("RECONX_CERTSPOTTER_API_KEY", "env-wins-1234")
	os.Unsetenv("RECONX_GITHUB_TOKEN")
	os.Unsetenv("RECONX_URLSCAN_API_KEY")

	if err := s.Set("GitHub", "ghp_abcdefghijklmnop"); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("certspotter", "file-value-9999"); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("nope", "x"); err == nil {
		t.Fatal("unknown key accepted")
	}
	if err := s.Set("urlscan", "has space"); err == nil {
		t.Fatal("whitespace accepted")
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("key file mode = %v, %v; want 0600", fi.Mode().Perm(), err)
		}
	}

	st, err := s.Statuses()
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Status{}
	for _, x := range st {
		by[x.Name] = x
		if strings.Contains(x.Hint, "abcdefgh") {
			t.Fatalf("status leaks key: %+v", x)
		}
	}
	if by["github"].Source != "file" || by["github"].Hint != "••••mnop" {
		t.Errorf("github status = %+v", by["github"])
	}
	if by["urlscan"].Source != "unset" {
		t.Errorf("urlscan status = %+v", by["urlscan"])
	}
	if cs := by["certspotter"]; cs.Source != "env" || !cs.Shadow {
		t.Errorf("certspotter status = %+v; env should win and shadow the file", cs)
	}

	applied, err := s.Apply()
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 1 || applied[0] != "github" {
		t.Errorf("applied = %v, want [github]", applied)
	}
	if os.Getenv("RECONX_GITHUB_TOKEN") != "ghp_abcdefghijklmnop" {
		t.Error("github token not exported")
	}
	if os.Getenv("RECONX_CERTSPOTTER_API_KEY") != "env-wins-1234" {
		t.Error("Apply overrode a user-set env var")
	}

	// Removing through SetAndApply clears the variable it had exported.
	if err := s.SetAndApply("github", ""); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.Get("github"); v != "" {
		t.Error("github key not removed from file")
	}
	if os.Getenv("RECONX_GITHUB_TOKEN") != "" {
		t.Error("env var not cleared after removal")
	}
	// ...but a user-exported variable survives removal of the stored key.
	if err := s.SetAndApply("certspotter", ""); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("RECONX_CERTSPOTTER_API_KEY") != "env-wins-1234" {
		t.Error("user env var was cleared")
	}
}

func TestMask(t *testing.T) {
	if got := Mask("short"); got != "•••••" {
		t.Errorf("Mask(short) = %q", got)
	}
	if got := Mask("0123456789abcdef"); got != "••••cdef" {
		t.Errorf("Mask = %q", got)
	}
}

func TestVerify(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/gh":
			if r.Header.Get("Authorization") != "Bearer good" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Write([]byte(`{"resources":{"code_search":{"limit":10,"remaining":9}}}`))
		case "/us":
			if r.Header.Get("API-Key") != "good" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.Write([]byte(`{"limits":{"search":{"day":{"limit":1000,"remaining":990}}}}`))
		case "/cs":
			w.WriteHeader(http.StatusTooManyRequests)
		}
	}))
	defer srv.Close()
	githubRateURL, urlscanQuotaURL, certspotterURL = srv.URL+"/gh", srv.URL+"/us", srv.URL+"/cs"

	ctx := context.Background()
	if r := Verify(ctx, "github", "good"); !r.OK || !strings.Contains(r.Detail, "9/10") {
		t.Errorf("github good = %+v", r)
	}
	if r := Verify(ctx, "github", "bad"); r.OK || !strings.Contains(r.Detail, "401") {
		t.Errorf("github bad = %+v", r)
	}
	if r := Verify(ctx, "urlscan", "good"); !r.OK || !strings.Contains(r.Detail, "990/1000") {
		t.Errorf("urlscan good = %+v", r)
	}
	if r := Verify(ctx, "certspotter", "x"); !r.OK || !strings.Contains(r.Detail, "429") {
		t.Errorf("certspotter 429 = %+v", r)
	}
	if r := Verify(ctx, "urlscan", ""); r.OK || r.Detail != "not set" {
		t.Errorf("empty = %+v", r)
	}
}

func TestThreatLensKeyLinkFollowsServer(t *testing.T) {
	link := func() string {
		sts, err := Open(filepath.Join(t.TempDir(), "keys.json")).Statuses()
		if err != nil {
			t.Fatal(err)
		}
		for _, st := range sts {
			if st.Name == "threatlens" {
				return st.GetURL
			}
		}
		return ""
	}
	t.Setenv("RECONX_THREATLENS_URL", "")
	if got := link(); got != "http://127.0.0.1:8000/ui/login" {
		t.Fatalf("default link = %q, want the sign-in page (it explains how to create a key)", got)
	}
	t.Setenv("RECONX_THREATLENS_URL", "https://tl.example.org/")
	if got := link(); got != "https://tl.example.org/ui/login" {
		t.Fatalf("configured link = %q", got)
	}
}
