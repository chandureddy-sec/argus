package wayback

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"reconx/pkg/models"
)

func TestWayback_Collect(t *testing.T) {
	mockJSON := `[
		["original"],
		["https://api.example.com/login"],
		["http://test.example.com:8080/path"],
		["https://out-of-scope.com/index.html"]
	]`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mockJSON))
	}))
	defer server.Close()

	provider := NewProvider(5 * time.Second)
	provider.baseURL = server.URL

	target := models.Target{
		Value: "example.com",
		Type:  models.TargetTypeDomain,
	}

	results, err := provider.Collect(context.Background(), target)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 in-scope results, got %d", len(results))
	}

	for _, r := range results {
		if r.Source != "wayback" {
			t.Errorf("expected source wayback, got %s", r.Source)
		}
		if r.Value != "api.example.com" && r.Value != "test.example.com" {
			t.Errorf("unexpected value %s", r.Value)
		}
	}
}
