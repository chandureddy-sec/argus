package githubcode

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"reconx/internal/providers"
	"reconx/pkg/models"
)

var target = models.Target{Value: "example.com", Type: models.TargetTypeDomain}

func provider(url, token string) *Provider {
	p := NewProvider(5 * time.Second)
	p.baseURL = url + "/search/code"
	p.token = token
	return p
}

func TestExtractHosts(t *testing.T) {
	text := `API_URL=https://API.example.com/v1
	const s = "https%3A%2F%2Fstaging.example.com%2Flogin";
	"url":"https:\/\/cdn.example.com\/x" /json.example.com
	mail: ops@mail.example.com, apex example.com.
	not ours: notexample.com example.com.evil.org bad-.example.com -x.example.com`
	got := ExtractHosts(text, "example.com")
	want := []string{"api.example.com", "staging.example.com", "cdn.example.com", "json.example.com", "mail.example.com", "example.com", "x.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ExtractHosts =\n %v\nwant\n %v", got, want)
	}
}

func TestSkippedWithoutToken(t *testing.T) {
	_, err := provider("http://unused", "").Collect(context.Background(), target)
	if !errors.Is(err, providers.ErrSkipped) || !strings.Contains(err.Error(), TokenEnv) {
		t.Errorf("expected ErrSkipped naming %s, got %v", TokenEnv, err)
	}
}

func page(items int, host string) string {
	var b strings.Builder
	b.WriteString(`{"total_count":150,"items":[`)
	for i := 0; i < items; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"html_url":"https://github.com/acme/repo%d/blob/main/f.env","repository":{"full_name":"acme/repo%d"},"text_matches":[{"fragment":"BASE=https://%s/api"}]}`, i%2, i%2, host)
	}
	b.WriteString(`]}`)
	return b.String()
}

func TestCollectPaginatesAndMerges(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if r.Header.Get("Authorization") != "Bearer ghp_test" || !strings.Contains(r.Header.Get("Accept"), "text-match") {
			t.Errorf("missing auth or text-match header")
		}
		if q := r.URL.Query().Get("q"); q != `"example.com"` {
			t.Errorf("query = %q", q)
		}
		w.Header().Set("X-RateLimit-Remaining", "8")
		switch r.URL.Query().Get("page") {
		case "1":
			_, _ = w.Write([]byte(page(100, "dev.example.com")))
		case "2":
			_, _ = w.Write([]byte(page(50, "vpn.example.com")))
		default:
			t.Error("requested a page past the last one")
		}
	}))
	defer srv.Close()

	results, err := provider(srv.URL, "ghp_test").Collect(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(results) != 2 {
		t.Fatalf("expected 2 pages and 2 hosts, got %d calls / %v", calls, results)
	}
	dev := results[0]
	if dev.Value != "dev.example.com" || dev.Source != "githubcode" || dev.Metadata["repos"] != "2" || len(strings.Fields(dev.Metadata["code_refs"])) != 2 {
		t.Errorf("unexpected merge: %+v", dev)
	}
}

func TestRateLimitStopsPaging(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("X-RateLimit-Remaining", "0")
		_, _ = w.Write([]byte(page(100, "dev.example.com")))
	}))
	defer srv.Close()

	results, err := provider(srv.URL, "ghp_test").Collect(context.Background(), target)
	if err != nil || len(results) != 1 || calls != 1 {
		t.Errorf("expected to stop after the budget-exhausting page: %d calls, %v, %v", calls, results, err)
	}
}

func TestErrorsDegradeGracefully(t *testing.T) {
	cases := map[string]struct {
		status    int
		remaining string
		want      string
	}{
		"bad token":    {http.StatusUnauthorized, "", "rejected the token"},
		"rate limited": {http.StatusForbidden, "0", "rate limit reached"},
		"validation":   {http.StatusUnprocessableEntity, "9", "422"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-RateLimit-Remaining", c.remaining)
				w.Header().Set("X-RateLimit-Reset", "1791349560")
				w.WriteHeader(c.status)
			}))
			defer srv.Close()
			_, err := provider(srv.URL, "ghp_test").Collect(context.Background(), target)
			if err == nil || !strings.Contains(err.Error(), c.want) || errors.Is(err, providers.ErrSkipped) {
				t.Errorf("got %v, want an error containing %q", err, c.want)
			}
		})
	}
}

func TestLaterPageFailureKeepsResults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "1" {
			w.Header().Set("X-RateLimit-Remaining", "8")
			_, _ = w.Write([]byte(page(100, "dev.example.com")))
			return
		}
		_, _ = w.Write([]byte(`{"items":[`))
	}))
	defer srv.Close()

	results, err := provider(srv.URL, "ghp_test").Collect(context.Background(), target)
	if err != nil || len(results) != 1 {
		t.Errorf("expected page-1 host despite page-2 failure, got %v / %v", results, err)
	}
}
