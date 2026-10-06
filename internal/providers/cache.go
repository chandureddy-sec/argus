package providers

import (
	"context"
	"sync"
	"time"
)

// Memo is a small in-process cache for public-source responses. Several scan
// stages read the same upstream data (e.g. crt.sh feeds both subdomain
// discovery and certificate analysis); Memo makes them share one request, and
// concurrent callers for the same key wait for the single in-flight fetch.
type Memo[T any] struct {
	ttl     time.Duration
	mu      sync.Mutex
	entries map[string]*memoEntry[T]
}

type memoEntry[T any] struct {
	done    chan struct{}
	value   T
	err     error
	fetched time.Time
}

// NewMemo creates a cache whose successful entries live for ttl.
func NewMemo[T any](ttl time.Duration) *Memo[T] {
	return &Memo[T]{ttl: ttl, entries: make(map[string]*memoEntry[T])}
}

// Get returns the cached value for key, or calls fetch once to obtain it.
// Errors are not cached, so a failed fetch is retried by the next caller.
func (m *Memo[T]) Get(ctx context.Context, key string, fetch func(context.Context) (T, error)) (T, error) {
	m.mu.Lock()
	if e, ok := m.entries[key]; ok {
		m.mu.Unlock()
		select {
		case <-e.done:
			if e.err == nil && time.Since(e.fetched) < m.ttl {
				return e.value, nil
			}
		case <-ctx.Done():
			var zero T
			return zero, ctx.Err()
		}
		m.mu.Lock()
		// Expired or failed: fall through and refetch, unless another caller
		// has already replaced the entry.
		if cur, ok := m.entries[key]; ok && cur != e {
			m.mu.Unlock()
			return m.Get(ctx, key, fetch)
		}
	}
	e := &memoEntry[T]{done: make(chan struct{})}
	m.entries[key] = e
	m.mu.Unlock()

	e.value, e.err = fetch(ctx)
	e.fetched = time.Now()
	close(e.done)
	if e.err != nil {
		m.mu.Lock()
		if m.entries[key] == e {
			delete(m.entries, key)
		}
		m.mu.Unlock()
	}
	return e.value, e.err
}
