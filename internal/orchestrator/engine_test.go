package orchestrator

import (
	"context"
	"errors"
	"testing"
	"time"

	"reconx/internal/providers"
	"reconx/pkg/models"
)

// stubProvider is a configurable in-memory provider for tests.
type stubProvider struct {
	name      string
	results   []models.RawResult
	err       error
	rateLimit time.Duration
	supports  bool
}

func (s *stubProvider) Name() string                { return s.name }
func (s *stubProvider) Supports(models.Target) bool { return s.supports }
func (s *stubProvider) RateLimit() time.Duration    { return s.rateLimit }
func (s *stubProvider) Collect(context.Context, models.Target) ([]models.RawResult, error) {
	return s.results, s.err
}

func TestRun_DedupMergesSourcesAndMetadata(t *testing.T) {
	p1 := &stubProvider{
		name:     "alpha",
		supports: true,
		results: []models.RawResult{
			{Source: "alpha", Value: "a.example.com", Type: models.AssetTypeSubdomain, Confidence: 0.5},
		},
	}
	p2 := &stubProvider{
		name:     "beta",
		supports: true,
		results: []models.RawResult{
			{Source: "beta", Value: "a.example.com", Type: models.AssetTypeSubdomain, Confidence: 0.9,
				Metadata: map[string]string{"not_before": "2024-01-02T00:00:00"}},
		},
	}

	e := NewEngine([]providers.Provider{p1, p2}, 5*time.Second)
	results, statuses, err := e.Run(context.Background(), models.Target{Value: "example.com", Type: models.TargetTypeDomain})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 deduped result, got %d", len(results))
	}
	got := results[0]
	if got.Confidence != 0.9 {
		t.Errorf("expected max confidence 0.9, got %v", got.Confidence)
	}
	if got.Metadata["not_before"] != "2024-01-02T00:00:00" {
		t.Errorf("expected merged metadata to survive dedup, got %v", got.Metadata)
	}
	if len(statuses) != 2 {
		t.Errorf("expected a status per supported provider, got %d", len(statuses))
	}
}

func TestRun_FailingProviderReportedNotFatal(t *testing.T) {
	ok := &stubProvider{name: "ok", supports: true,
		results: []models.RawResult{{Source: "ok", Value: "x.example.com", Type: models.AssetTypeSubdomain}}}
	bad := &stubProvider{name: "bad", supports: true, err: errors.New("boom")}

	e := NewEngine([]providers.Provider{ok, bad}, 5*time.Second)
	results, statuses, err := e.Run(context.Background(), models.Target{Value: "example.com", Type: models.TargetTypeDomain})
	if err != nil {
		t.Fatalf("a provider failure must not fail the run: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result from the healthy provider, got %d", len(results))
	}

	var sawErr bool
	for _, s := range statuses {
		if s.Name == "bad" && s.Err != nil {
			sawErr = true
		}
	}
	if !sawErr {
		t.Error("expected the failing provider's error to be surfaced in statuses")
	}
}

func TestRateLimiter_EnforcesInterval(t *testing.T) {
	rl := newRateLimiter()
	const interval = 50 * time.Millisecond

	start := time.Now()
	rl.wait(context.Background(), "p", interval) // first is immediate
	rl.wait(context.Background(), "p", interval) // second must wait ~interval
	elapsed := time.Since(start)

	if elapsed < interval {
		t.Errorf("expected second call to be delayed by at least %v, waited %v", interval, elapsed)
	}
}

func TestRateLimiter_ContextCancelAborts(t *testing.T) {
	rl := newRateLimiter()
	rl.wait(context.Background(), "p", time.Hour) // reserve a far-future slot

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	start := time.Now()
	rl.wait(ctx, "p", time.Hour)
	if time.Since(start) > time.Second {
		t.Error("wait should return promptly when context is cancelled")
	}
}
