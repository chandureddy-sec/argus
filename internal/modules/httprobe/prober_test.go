package httprobe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProbeURL_ParsesResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.0")
		w.Header().Set("X-Powered-By", "PHP/8.2")
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><head><title>Hello World</title></head><body>hi</body></html>"))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := ProbeURL(ctx, srv.URL)
	if err != nil {
		t.Fatalf("ProbeURL error: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", res.StatusCode)
	}
	if res.Title != "Hello World" {
		t.Errorf("title = %q, want %q", res.Title, "Hello World")
	}
	if res.Server != "nginx/1.25.0" {
		t.Errorf("server = %q", res.Server)
	}
	if len(res.Cookies) != 1 || res.Cookies[0].Name != "sid" {
		t.Fatalf("expected 1 cookie named sid, got %+v", res.Cookies)
	}
	c := res.Cookies[0]
	if !c.Secure || !c.HTTPOnly || c.SameSite != "Strict" {
		t.Errorf("cookie flags not parsed: %+v", c)
	}
}

func TestProbeURL_FollowsRedirectChain(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<title>Final</title>"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := ProbeURL(ctx, srv.URL)
	if err != nil {
		t.Fatalf("ProbeURL error: %v", err)
	}
	if len(res.RedirectChain) < 2 {
		t.Errorf("expected a redirect chain of >=2, got %v", res.RedirectChain)
	}
	if res.Title != "Final" {
		t.Errorf("expected to land on Final page, title = %q", res.Title)
	}
}
