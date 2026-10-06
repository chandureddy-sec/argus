package hackertarget

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"reconx/pkg/models"
)

func TestHackerTarget_Collect(t *testing.T) {
	mockResponse := `api.example.com,93.184.216.34
test.example.com,93.184.216.35
out-of-scope.com,1.2.3.4
`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mockResponse))
	}))
	defer server.Close()

	provider := NewProvider(5 * time.Second)
	provider.baseURL = server.URL + "/?q="

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
		if r.Source != "hackertarget" {
			t.Errorf("expected source hackertarget, got %s", r.Source)
		}
		if r.Value != "api.example.com" && r.Value != "test.example.com" {
			t.Errorf("unexpected value %s", r.Value)
		}
	}
}
