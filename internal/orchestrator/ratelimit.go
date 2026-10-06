package orchestrator

import (
	"context"
	"sync"
	"time"
)

// rateLimiter enforces a minimum interval between consecutive calls to the same
// provider, keyed by provider name. It is process-wide so that repeated Runs
// (e.g. scanning several targets in one interactive session) still respect each
// provider's declared RateLimit and avoid tripping free-API throttles or bans.
type rateLimiter struct {
	mu       sync.Mutex
	nextFree map[string]time.Time
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{nextFree: make(map[string]time.Time)}
}

// defaultLimiter is shared by all engines in the process.
var defaultLimiter = newRateLimiter()

// wait blocks until the named provider is allowed to be called again, then
// reserves the next slot. A non-positive interval disables limiting. wait
// returns early if the context is cancelled.
func (r *rateLimiter) wait(ctx context.Context, name string, interval time.Duration) {
	if interval <= 0 {
		return
	}

	r.mu.Lock()
	now := time.Now()
	earliest, ok := r.nextFree[name]
	if !ok || !earliest.After(now) {
		// Free to go now; reserve the slot after this call.
		r.nextFree[name] = now.Add(interval)
		r.mu.Unlock()
		return
	}
	// Reserve our slot and wait for it.
	r.nextFree[name] = earliest.Add(interval)
	delay := earliest.Sub(now)
	r.mu.Unlock()

	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}
