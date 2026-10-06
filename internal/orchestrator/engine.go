package orchestrator

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"reconx/internal/providers"
	"reconx/pkg/models"
)

// Engine manages concurrent fan-out to all registered OSINT providers.
type Engine struct {
	providers []providers.Provider
	timeout   time.Duration

	limiter *rateLimiter
}

// ProviderStatus records the per-provider outcome of a Run so callers can
// surface which sources succeeded, which failed, and how many results each
// contributed — instead of silently dropping failures.
type ProviderStatus struct {
	Name    string
	Results int
	Elapsed time.Duration
	Err     error
}

// NewEngine initializes the orchestrator engine.
func NewEngine(providersList []providers.Provider, timeout time.Duration) *Engine {
	if timeout <= 0 {
		timeout = 40 * time.Second
	}
	return &Engine{
		providers: providersList,
		timeout:   timeout,
		limiter:   defaultLimiter,
	}
}

// Run executes all supported providers concurrently against the target. It
// returns the deduplicated raw results and a per-provider status report. The
// error is non-nil only for a whole-run failure; individual provider failures
// are reported in the returned statuses and never abort the run.
func (e *Engine) Run(ctx context.Context, t models.Target) ([]models.RawResult, []ProviderStatus, error) {
	raw, statuses, err := e.RunRaw(ctx, t)
	if err != nil {
		return nil, statuses, err
	}
	return mergeResults(raw), statuses, nil
}

// RunRaw is Run without cross-provider merging: each provider's results are
// returned as emitted, so per-source provenance and observation dates survive
// for the evidence and confidence models.
func (e *Engine) RunRaw(ctx context.Context, t models.Target) ([]models.RawResult, []ProviderStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	var wg sync.WaitGroup
	type outcome struct {
		results []models.RawResult
		status  ProviderStatus
	}
	outChan := make(chan outcome, len(e.providers))

	for _, p := range e.providers {
		if !p.Supports(t) {
			continue
		}

		wg.Add(1)
		go func(prov providers.Provider) {
			defer wg.Done()

			// Honor the provider's declared minimum interval between calls.
			e.limiter.wait(ctx, prov.Name(), prov.RateLimit())

			slog.Debug("invoking provider", slog.String("provider", prov.Name()), slog.String("target", t.Value))

			start := time.Now()
			res, err := prov.Collect(ctx, t)
			elapsed := time.Since(start)

			status := ProviderStatus{Name: prov.Name(), Elapsed: elapsed, Err: err}
			if err != nil {
				slog.Warn("provider query failed (degraded gracefully)",
					slog.String("provider", prov.Name()),
					slog.String("error", err.Error()),
				)
			} else {
				status.Results = len(res)
			}
			outChan <- outcome{results: res, status: status}
		}(p)
	}

	wg.Wait()
	close(outChan)

	var raw []models.RawResult
	statuses := make([]ProviderStatus, 0, len(e.providers))
	for o := range outChan {
		statuses = append(statuses, o.status)
		raw = append(raw, o.results...)
	}
	return raw, statuses, nil
}

// mergeResults deduplicates results by value and type, combining sources and
// metadata across providers.
func mergeResults(raw []models.RawResult) []models.RawResult {
	seen := make(map[string]models.RawResult)
	for _, item := range raw {
		key := item.Value + ":" + string(item.Type)
		if existing, ok := seen[key]; ok {
			// Combine sources
			existing.Source = existing.Source + "," + item.Source
			if item.Confidence > existing.Confidence {
				existing.Confidence = item.Confidence
			}
			// Merge metadata so date hints (e.g. crt.sh not_before) survive
			// regardless of which provider's result arrived first.
			if len(item.Metadata) > 0 {
				if existing.Metadata == nil {
					existing.Metadata = make(map[string]string, len(item.Metadata))
				}
				for k, v := range item.Metadata {
					if v != "" {
						if _, has := existing.Metadata[k]; !has {
							existing.Metadata[k] = v
						}
					}
				}
			}
			seen[key] = existing
		} else {
			seen[key] = item
		}
	}

	results := make([]models.RawResult, 0, len(seen))
	for _, item := range seen {
		results = append(results, item)
	}
	return results
}
