package providers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func fastCfg() RetryConfig {
	return RetryConfig{MaxAttempts: 3, BaseDelay: 1 * time.Millisecond, MaxDelay: 5 * time.Millisecond}
}

func TestDoWithRetry_RecoversAfterTransient502(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) < 3 {
			w.WriteHeader(http.StatusBadGateway) // 502 twice
			return
		}
		w.WriteHeader(http.StatusOK) // succeed on the 3rd
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	resp, err := DoWithRetry(context.Background(), srv.Client(), req, fastCfg())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 after retries, got %d", resp.StatusCode)
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("expected 3 attempts, got %d", got)
	}
}

func TestDoWithRetry_NoRetryOn404(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	resp, err := DoWithRetry(context.Background(), srv.Client(), req, fastCfg())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 passed through, got %d", resp.StatusCode)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("404 must not be retried: expected 1 call, got %d", got)
	}
}

func TestDoWithRetry_ExhaustsAndReturnsLastStatus(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusServiceUnavailable) // always 503
	}))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	resp, err := DoWithRetry(context.Background(), srv.Client(), req, fastCfg())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected last 503 returned, got %d", resp.StatusCode)
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("expected MaxAttempts=3 calls, got %d", got)
	}
}

func TestDoWithRetry_ContextCancelStops(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway) // always retryable
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	cfg := RetryConfig{MaxAttempts: 5, BaseDelay: time.Hour, MaxDelay: time.Hour}
	_, err := DoWithRetry(ctx, srv.Client(), req, cfg)
	if err == nil {
		t.Error("expected context cancellation error, got nil")
	}
}

func TestDoWithRetry_LongRetryAfterGivesUpImmediately(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Retry-After", "3600") // hourly quota exhausted
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	start := time.Now()
	resp, err := DoWithRetry(context.Background(), srv.Client(), req, DefaultRetryConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests || calls != 1 {
		t.Errorf("expected one 429 attempt, got status %d after %d calls", resp.StatusCode, calls)
	}
	if time.Since(start) > 2*time.Second {
		t.Error("caller was stalled by a long Retry-After")
	}
}
