package dns

import (
	"testing"

	"reconx/internal/config"
)

func TestNewRecordResolver_Selection(t *testing.T) {
	cases := map[string]string{
		"":       "system", // default
		"system": "system",
		"google": "google",
		"doh":    "google",
		"bogus":  "system", // unknown falls back, never disables resolution
		"GOOGLE": "google", // case-insensitive
	}
	for provider, wantName := range cases {
		cfg := config.DefaultConfig()
		cfg.DNS.Provider = provider
		if got := NewRecordResolver(cfg).Name(); got != wantName {
			t.Errorf("provider %q -> resolver %q, want %q", provider, got, wantName)
		}
	}
}

func TestDefaultConfigIsSystem(t *testing.T) {
	if got := config.DefaultConfig().DNS.Provider; got != "system" {
		t.Errorf("default dns.provider = %q, want system (opt-in)", got)
	}
}
