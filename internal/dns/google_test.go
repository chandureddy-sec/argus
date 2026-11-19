package dns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type answer map[string]any

// dohServer returns an httptest server whose per-type behaviour is supplied by h.
func dohServer(h func(name, typ string) (status int, answers []answer)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status, answers := h(r.URL.Query().Get("name"), r.URL.Query().Get("type"))
		w.Header().Set("Content-Type", "application/dns-json")
		_ = json.NewEncoder(w).Encode(map[string]any{"Status": status, "TC": false, "Answer": answers})
	}))
}

func recByType(res *Result, typ string) []Record {
	var out []Record
	for _, r := range res.Records {
		if r.Type == typ {
			out = append(out, r)
		}
	}
	return out
}

func TestGoogleDoH_Resolve_Success(t *testing.T) {
	srv := dohServer(func(name, typ string) (int, []answer) {
		fq := name + "."
		switch typ {
		case "A":
			return 0, []answer{{"name": fq, "type": 1, "TTL": 300, "data": "93.184.216.34"}}
		case "AAAA":
			return 0, []answer{{"name": fq, "type": 28, "TTL": 300, "data": "2606:2800:220:1:248:1893:25c8:1946"}}
		case "MX":
			return 0, []answer{{"name": fq, "type": 15, "TTL": 3600, "data": "10 mail.example.com."}}
		case "NS":
			return 0, []answer{{"name": fq, "type": 2, "TTL": 3600, "data": "a.iana-servers.net."}}
		case "SOA":
			return 0, []answer{{"name": fq, "type": 6, "TTL": 3600, "data": "ns.icann.org. noc.dns.icann.org. 2024010101 7200 3600 1209600 3600"}}
		case "CAA":
			return 0, []answer{{"name": fq, "type": 257, "TTL": 3600, "data": "0 issue \"letsencrypt.org\""}}
		case "TXT":
			if strings.HasPrefix(name, "_dmarc.") {
				return 0, []answer{{"name": fq, "type": 16, "TTL": 3600, "data": "\"v=DMARC1; p=reject\""}}
			}
			return 0, []answer{{"name": fq, "type": 16, "TTL": 3600, "data": "\"v=spf1 \" \"-all\""}}
		}
		return 0, nil
	})
	defer srv.Close()

	g := NewGoogleDoH(srv.URL, 5*time.Second, srv.Client())
	res, err := g.Resolve(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Resolver != "google" {
		t.Errorf("Resolver = %q, want google", res.Resolver)
	}
	if res.Status != "NOERROR" {
		t.Errorf("Status = %q, want NOERROR", res.Status)
	}
	if res.QueriedAt.IsZero() {
		t.Error("QueriedAt not stamped")
	}
	if a := recByType(res, "A"); len(a) != 1 || a[0].Value != "93.184.216.34" || a[0].TTL != 300 {
		t.Errorf("A record = %+v", a)
	}
	if mx := recByType(res, "MX"); len(mx) != 1 || mx[0].Value != "10 mail.example.com" {
		t.Errorf("MX trailing dot not trimmed: %+v", mx)
	}
	if soa := recByType(res, "SOA"); len(soa) != 1 || soa[0].Value != "Primary NS: ns.icann.org, Admin: noc.dns.icann.org, Serial: 2024010101" {
		t.Errorf("SOA format = %+v", soa)
	}
	if caa := recByType(res, "CAA"); len(caa) != 1 || caa[0].Value != `issue "letsencrypt.org"` {
		t.Errorf("CAA format = %+v", caa)
	}
	if res.SecurityRecords.SPF != "v=spf1 -all" {
		t.Errorf("SPF = %q (TXT concat/unquote failed)", res.SecurityRecords.SPF)
	}
	if res.SecurityRecords.DMARC != "v=DMARC1; p=reject" {
		t.Errorf("DMARC = %q", res.SecurityRecords.DMARC)
	}
}

func TestGoogleDoH_StatusCodes(t *testing.T) {
	for _, tc := range []struct {
		code int
		want string
	}{{3, "NXDOMAIN"}, {2, "SERVFAIL"}, {5, "REFUSED"}, {9, "RCODE9"}} {
		srv := dohServer(func(string, string) (int, []answer) { return tc.code, nil })
		g := NewGoogleDoH(srv.URL, 5*time.Second, srv.Client())
		res, err := g.Resolve(context.Background(), "nope.example")
		srv.Close()
		if err != nil {
			t.Fatalf("code %d: unexpected error %v", tc.code, err)
		}
		if res.Status != tc.want {
			t.Errorf("code %d: Status = %q, want %q", tc.code, res.Status, tc.want)
		}
		if len(res.Records) != 0 {
			t.Errorf("code %d: expected no records, got %d", tc.code, len(res.Records))
		}
	}
}

func TestGoogleDoH_MalformedIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{ this is not json"))
	}))
	defer srv.Close()
	g := NewGoogleDoH(srv.URL, 5*time.Second, srv.Client())
	if _, err := g.Resolve(context.Background(), "example.com"); err == nil {
		t.Fatal("expected an error for malformed JSON on every query")
	}
}

func TestGoogleDoH_HTTPErrorIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	g := NewGoogleDoH(srv.URL, 5*time.Second, srv.Client())
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, err := g.Resolve(ctx, "example.com"); err == nil {
		t.Fatal("expected an error when every query returns HTTP 500")
	}
}

func TestGoogleDoH_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	g := NewGoogleDoH(srv.URL, 5*time.Second, srv.Client())
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, err := g.Resolve(ctx, "example.com"); err == nil {
		t.Fatal("expected a timeout error")
	}
}

func TestGoogleDoH_SizeCapDoesNotPanic(t *testing.T) {
	// A response far larger than maxDoHBody must be truncated (which yields a
	// JSON error), never read unbounded or panic.
	huge := `{"Status":0,"Answer":[{"name":"x.","type":16,"TTL":1,"data":"` + strings.Repeat("A", maxDoHBody*2) + `"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(huge))
	}))
	defer srv.Close()
	g := NewGoogleDoH(srv.URL, 5*time.Second, srv.Client())
	// Should not hang or panic; an oversized body fails to parse -> error.
	if _, err := g.Resolve(context.Background(), "example.com"); err == nil {
		t.Fatal("expected truncated oversized body to error, not succeed")
	}
}

func TestUnquoteTXT(t *testing.T) {
	cases := map[string]string{
		`"v=spf1 -all"`:         "v=spf1 -all",
		`"part1" "part2"`:       "part1part2",
		`no-quotes-here`:        "no-quotes-here",
		`"a" "b" "c"`:           "abc",
		`"v=spf1 " "include:x"`: "v=spf1 include:x",
	}
	for in, want := range cases {
		if got := unquoteTXT(in); got != want {
			t.Errorf("unquoteTXT(%q) = %q, want %q", in, got, want)
		}
	}
}
