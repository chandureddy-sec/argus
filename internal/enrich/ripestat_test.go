package enrich

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func ripestatServer(t *testing.T, neighbourCalls *int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("sourceapp") != "reconx" {
			t.Errorf("sourceapp missing on %s", r.URL)
		}
		res := r.URL.Query().Get("resource")
		switch {
		case strings.HasPrefix(r.URL.Path, "/prefix-overview/"):
			switch res {
			case "93.184.216.34", "93.184.216.40":
				_, _ = w.Write([]byte(`{"status":"ok","data":{"announced":true,"resource":"93.184.216.0/24","asns":[{"asn":15133,"holder":"EDGECAST - Edgecast Inc."}]}}`))
			case "93.184.216.35":
				w.WriteHeader(http.StatusBadRequest)
			case "93.184.216.36":
				_, _ = w.Write([]byte(`{"status":"error","data":{}}`))
			default:
				_, _ = w.Write([]byte(`{"status":"ok","data":`))
			}
		case strings.HasPrefix(r.URL.Path, "/rir/"):
			_, _ = w.Write([]byte(`{"status":"ok","data":{"rirs":[{"rir":"ripe ncc"}]}}`))
		case strings.HasPrefix(r.URL.Path, "/asn-neighbours/"):
			atomic.AddInt32(neighbourCalls, 1)
			if res != "AS15133" {
				t.Errorf("neighbours queried for %s", res)
			}
			_, _ = w.Write([]byte(`{"status":"ok","data":{"neighbours":[
				{"asn":3356,"type":"left","power":50},{"asn":64500,"type":"right","power":99},
				{"asn":174,"type":"left","power":80},{"asn":6939,"type":"left","power":10}]}}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
}

func testRIPEstat(url string) *RIPEstat {
	r := NewRIPEstat(5 * time.Second)
	r.baseURL = url + "/"
	r.maxUpstream = 2
	return r
}

func TestRIPEstatLookup(t *testing.T) {
	var calls int32
	srv := ripestatServer(t, &calls)
	defer srv.Close()

	info, err := testRIPEstat(srv.URL).Lookup(context.Background(), "93.184.216.34")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if info.Prefix != "93.184.216.0/24" || !info.Announced || info.Holder != "EDGECAST - Edgecast Inc." || len(info.ASNs) != 1 || info.ASNs[0] != "15133" {
		t.Errorf("prefix data wrong: %+v", info)
	}
	if info.RIR != "RIPE NCC" {
		t.Errorf("RIR = %q", info.RIR)
	}
	// Left neighbours only, strongest first, capped.
	if strings.Join(info.Upstreams, ",") != "AS174,AS3356" {
		t.Errorf("upstreams = %v", info.Upstreams)
	}
}

func TestRIPEstatBatchDegradesGracefully(t *testing.T) {
	var calls int32
	srv := ripestatServer(t, &calls)
	defer srv.Close()

	ips := []string{"93.184.216.34", "93.184.216.40", "93.184.216.34", // two IPs, one origin ASN
		"93.184.216.35",              // HTTP 400
		"93.184.216.36",              // status != ok
		"93.184.216.37",              // malformed JSON
		"10.1.2.3", "::1", "garbage"} // never sent
	got, err := testRIPEstat(srv.URL).LookupBatch(context.Background(), ips)
	if err == nil || !strings.Contains(err.Error(), "3 lookup(s) failed") {
		t.Errorf("expected 3 failures summarised, got %v", err)
	}
	if len(got) != 2 || got["93.184.216.34"] == nil || got["93.184.216.40"] == nil {
		t.Errorf("unexpected results: %v", got)
	}
	if calls != 1 {
		t.Errorf("upstreams should be fetched once per ASN, got %d calls", calls)
	}
}
