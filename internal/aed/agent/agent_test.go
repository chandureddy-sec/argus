package agent

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func TestSendHeartbeat(t *testing.T) {
	var mu sync.Mutex
	var seqs, nonces, bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/aed/heartbeat" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		seqs = append(seqs, r.Header.Get("X-AED-Seq"))
		nonces = append(nonces, r.Header.Get("X-AED-Nonce"))
		bodies = append(bodies, string(b))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(Config{GatewayURL: srv.URL, AgentID: "agent-1", Version: "0.1"}, srv.Client())
	if err := c.SendHeartbeat(context.Background()); err != nil {
		t.Fatalf("beat 1: %v", err)
	}
	if err := c.SendHeartbeat(context.Background()); err != nil {
		t.Fatalf("beat 2: %v", err)
	}

	if len(seqs) != 2 {
		t.Fatalf("want 2 beats, got %d", len(seqs))
	}
	s0, _ := strconv.ParseInt(seqs[0], 10, 64)
	s1, _ := strconv.ParseInt(seqs[1], 10, 64)
	if s1 <= s0 {
		t.Errorf("seq must strictly increase: %d then %d", s0, s1)
	}
	if nonces[0] == "" || nonces[0] == nonces[1] {
		t.Errorf("nonce must be present and unique: %q %q", nonces[0], nonces[1])
	}
	if !strings.Contains(bodies[0], `"version":"0.1"`) {
		t.Errorf("body missing version: %s", bodies[0])
	}
}

func TestSendHeartbeatErrorsOnNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	c := New(Config{GatewayURL: srv.URL, Version: "0.1"}, srv.Client())
	if err := c.SendHeartbeat(context.Background()); err == nil {
		t.Fatal("expected an error when the gateway returns 503")
	}
}

func TestNextSeqStrictlyIncreasing(t *testing.T) {
	c := New(Config{GatewayURL: "http://x"}, nil)
	prev := int64(0)
	for i := 0; i < 2000; i++ {
		s := c.nextSeq()
		if s <= prev {
			t.Fatalf("seq not strictly increasing at %d: %d <= %d", i, s, prev)
		}
		prev = s
	}
}
