package crawler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestExtractForms_LoginAndCSRF(t *testing.T) {
	base, _ := url.Parse("https://ex.com/")
	html := `<form action="/login" method="post">
		<input name="username" type="text">
		<input name="password" type="password">
		<input name="csrf_token" type="hidden" value="x">
	</form>`
	forms := extractForms(html, "https://ex.com/login-page", base)
	if len(forms) != 1 {
		t.Fatalf("expected 1 form, got %d", len(forms))
	}
	f := forms[0]
	if f.Method != "POST" {
		t.Errorf("method = %q, want POST", f.Method)
	}
	if !f.IsLogin {
		t.Error("form with a password field should be flagged IsLogin")
	}
	if !f.HasCSRFToken {
		t.Error("form with csrf_token field should be flagged HasCSRFToken")
	}
	if !strings.HasSuffix(f.Action, "/login") {
		t.Errorf("action not resolved: %q", f.Action)
	}
}

func TestExtractForms_FileUpload(t *testing.T) {
	base, _ := url.Parse("https://ex.com/")
	html := `<form action="/upload" method="post" enctype="multipart/form-data">
		<input name="file" type="file">
	</form>`
	forms := extractForms(html, "https://ex.com/", base)
	if len(forms) != 1 || !forms[0].IsFileUpload {
		t.Fatalf("expected a file-upload form, got %+v", forms)
	}
}

func TestStripTrackingParams(t *testing.T) {
	out := stripTrackingParams("utm_source=news&page=2&fbclid=abc&id=7")
	if strings.Contains(out, "utm_source") || strings.Contains(out, "fbclid") {
		t.Errorf("tracking params not stripped: %q", out)
	}
	if !strings.Contains(out, "page=2") || !strings.Contains(out, "id=7") {
		t.Errorf("legitimate params were lost: %q", out)
	}
}

func TestCrawl_WalksSameOriginAndFindsForm(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body>
			<a href="/about">About</a>
			<form action="/login" method="post"><input type="password" name="pw"></form>
		</body></html>`))
	})
	mux.HandleFunc("/about", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body><h1>About</h1></body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	opts := DefaultOptions()
	opts.MaxDepth = 2
	opts.MaxPages = 10

	res, err := Crawl(ctx, srv.URL, opts)
	if err != nil {
		t.Fatalf("Crawl error: %v", err)
	}
	if len(res.Pages) < 2 {
		t.Errorf("expected to crawl at least 2 pages (root + about), got %d", len(res.Pages))
	}
	if len(res.Forms) < 1 {
		t.Fatalf("expected to discover the login form, got %d forms", len(res.Forms))
	}
	if !res.Forms[0].IsLogin {
		t.Error("discovered form should be flagged IsLogin")
	}
}
