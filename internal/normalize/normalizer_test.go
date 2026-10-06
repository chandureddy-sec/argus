package normalize

import (
	"testing"

	"reconx/pkg/models"
)

func TestNormalizeAndDedup(t *testing.T) {
	rawInputs := []models.RawResult{
		{
			Source:     "crtsh",
			Value:      "*.api.example.com",
			Type:       models.AssetTypeSubdomain,
			Confidence: 0.70,
		},
		{
			Source:     "hackertarget",
			Value:      "api.example.com",
			Type:       models.AssetTypeSubdomain,
			Confidence: 0.80,
		},
		{
			Source:     "alienvault",
			Value:      "API.EXAMPLE.COM",
			Type:       models.AssetTypeSubdomain,
			Confidence: 0.75,
		},
		{
			Source:     "crtsh",
			Value:      "malicious-out-of-scope.com",
			Type:       models.AssetTypeSubdomain,
			Confidence: 0.50,
		},
	}

	opts := DefaultOptions("example.com")
	normalized := NormalizeAndDedup(rawInputs, opts)

	if len(normalized) != 1 {
		t.Fatalf("expected 1 normalized asset, got %d", len(normalized))
	}

	asset := normalized[0]
	if asset.Asset != "api.example.com" {
		t.Errorf("expected asset value 'api.example.com', got %q", asset.Asset)
	}

	expectedSources := map[string]bool{
		"crtsh":        false,
		"hackertarget": false,
		"alienvault":   false,
	}

	for _, s := range asset.Sources {
		if _, exists := expectedSources[s]; exists {
			expectedSources[s] = true
		}
	}

	for s, found := range expectedSources {
		if !found {
			t.Errorf("expected source %q was not merged", s)
		}
	}

	// 3 sources should boost confidence score
	if asset.Confidence <= 0.80 {
		t.Errorf("expected boosted confidence > 0.80, got %.2f", asset.Confidence)
	}
}
