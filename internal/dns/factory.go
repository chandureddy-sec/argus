package dns

import (
	"net/http"
	"strings"
	"time"

	"reconx/internal/config"
)

// NewRecordResolver returns the DNS record-resolver provider selected by cfg.
// This is the single place that maps config to a concrete provider, so callers
// depend only on the RecordResolver interface and no provider is hardcoded.
// An unknown or empty provider falls back to the system (port-53) resolver, so
// a typo never silently disables DNS resolution.
func NewRecordResolver(cfg *config.Config) RecordResolver {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	switch strings.ToLower(strings.TrimSpace(cfg.DNS.Provider)) {
	case "google", "doh":
		return NewGoogleDoH(cfg.DNS.DoHEndpoint, timeout, &http.Client{Timeout: timeout})
	default:
		return NewResolver(cfg.Resolvers, timeout)
	}
}
