package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"reconx/pkg/models"
)

func TestStorage_SaveScanAndDiff(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_reconx.db")

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	target := &models.Target{
		Value: "example.com",
		Type:  models.TargetTypeDomain,
	}

	// 1st scan
	graph1 := &models.Graph{
		TotalAssets: 2,
		LiveAssets:  1,
		Nodes: []models.CorrelatedAsset{
			{
				Hostname:    "api.example.com",
				IsAlive:     true,
				ResolvedIPs: []string{"93.184.216.34"},
				Sources:     []string{"crtsh"},
				Confidence:  0.8,
			},
			{
				Hostname:    "test.example.com",
				IsAlive:     false,
				ResolvedIPs: []string{},
				Sources:     []string{"anubis"},
				Confidence:  0.6,
			},
		},
	}

	diff1, err := db.SaveScan(ctx, target, graph1, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("1st SaveScan failed: %v", err)
	}
	if diff1 != nil {
		t.Errorf("expected nil diff for first scan, got %+v", diff1)
	}

	// 2nd scan with a newly discovered host
	graph2 := &models.Graph{
		TotalAssets: 3,
		LiveAssets:  2,
		Nodes: []models.CorrelatedAsset{
			{
				Hostname:    "api.example.com",
				IsAlive:     true,
				ResolvedIPs: []string{"93.184.216.34"},
				Sources:     []string{"crtsh"},
				Confidence:  0.8,
			},
			{
				Hostname:    "test.example.com",
				IsAlive:     false,
				ResolvedIPs: []string{},
				Sources:     []string{"anubis"},
				Confidence:  0.6,
			},
			{
				Hostname:    "admin.example.com",
				IsAlive:     true,
				ResolvedIPs: []string{"93.184.216.35"},
				Sources:     []string{"hackertarget"},
				Confidence:  0.9,
			},
		},
	}

	diff2, err := db.SaveScan(ctx, target, graph2, 600*time.Millisecond)
	if err != nil {
		t.Fatalf("2nd SaveScan failed: %v", err)
	}
	if diff2 == nil {
		t.Fatal("expected diff on 2nd scan, got nil")
	}
	if len(diff2.NewAssets) != 1 || diff2.NewAssets[0] != "admin.example.com" {
		t.Errorf("expected 1 new asset admin.example.com, got: %+v", diff2.NewAssets)
	}
}
