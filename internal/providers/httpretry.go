package providers

import (
	"context"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"time"
)

// RetryConfig controls transient-failure retries for provider HTTP calls.
type RetryConfig struct {
	MaxAttempts int           // total attempts, including the first
	BaseDelay   time.Duration // backoff for the first retry
	MaxDelay    time.Duration // cap on any single backoff
}

// DefaultRetryConfig is a conservative policy suited to free OSINT APIs that
// frequently return 502/503/429 under load (e.g. crt.sh).
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts: 3,
		BaseDelay:   600 * time.Millisecond,
		MaxDelay:    5 * time.Second,
	}
}

// retryableStatus reports whether an HTTP status warrants a retry. These are
// transient server-side / throttling conditions; 4xx client errors such as 400
// or 404 are left to the caller (a genuine 404 won't improve on retry).
func retryableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests, // 429
		http.StatusInternalServerError, // 500
		http.StatusBadGateway,          // 502
		http.StatusServiceUnavailable,  // 503
		http.StatusGatewayTimeout:      // 504
		return true
	}
	return false
}

// DoWithRetry issues req using client, retrying transient network errors and
// retryable HTTP statuses with exponential backoff and jitter. It honors the
// Retry-After header when present and aborts promptly if ctx is cancelled. The
// request must have a nil or rewindable body (true for all GET callers here).
//
// On success it returns the final response; the caller still owns closing the
// body. When every attempt fails transiently it returns the last response (so
// the caller can inspect the status) or the last error.
func DoWithRetry(ctx context.Context, client *http.Client, req *http.Request, cfg RetryConfig) (*http.Response, error) {
	if cfg.MaxAttempts < 1 {
		cfg.MaxAttempts = 1
	}

	var lastResp *http.Response
	var lastErr error

	for attempt := 1; attempt <= cfg.MaxAttempts; attempt++ {
		attemptReq := req.Clone(ctx)

		resp, err := client.Do(attemptReq)
		if err == nil && !retryableStatus(resp.StatusCode) {
			return resp, nil // success, or a non-retryable status
		}

		lastResp, lastErr = resp, err

		// No retries left: hand back whatever we last got.
		if attempt == cfg.MaxAttempts {
			break
		}

		// Decide how long to wait before the next attempt.
		delay := backoffDelay(cfg, attempt)
		if resp != nil {
			if ra := parseRetryAfter(resp.Header.Get("Retry-After")); ra > 0 {
				// A server asking for longer than we would ever back off (e.g.
				// an hourly quota) won't recover within a scan: give up now
				// and hand back the response rather than stall the caller.
				if ra > cfg.MaxDelay {
					return resp, nil
				}
				delay = ra
			}
			// Drain and close the body so the connection can be reused.
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			lastResp = nil
		}

		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		}
	}

	return lastResp, lastErr
}

// backoffDelay computes an exponential backoff with up to +50% jitter, capped
// at cfg.MaxDelay. attempt is 1-based.
func backoffDelay(cfg RetryConfig, attempt int) time.Duration {
	delay := cfg.BaseDelay << (attempt - 1) // BaseDelay * 2^(attempt-1)
	if delay <= 0 || delay > cfg.MaxDelay {
		delay = cfg.MaxDelay
	}
	jitter := time.Duration(rand.Int63n(int64(delay/2) + 1))
	return delay + jitter
}

// parseRetryAfter interprets a Retry-After header given as delta-seconds.
// Returns 0 when absent or not a plain integer (HTTP-date form is ignored).
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	return 0
}
