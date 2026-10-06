package portscan

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestKnownService(t *testing.T) {
	cases := map[int]string{22: "ssh", 80: "http", 443: "https"}
	for port, want := range cases {
		if got := KnownService(port); got != want {
			t.Errorf("KnownService(%d) = %q, want %q", port, got, want)
		}
	}
}

func TestScanPorts_DetectsOpenAndClosed(t *testing.T) {
	// Open a listener on an ephemeral port so we have one known-open port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to open test listener: %v", err)
	}
	defer ln.Close()
	openPort := ln.Addr().(*net.TCPAddr).Port

	// Find a very likely-closed port by opening then immediately closing one.
	tmp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to open temp listener: %v", err)
	}
	closedPort := tmp.Addr().(*net.TCPAddr).Port
	tmp.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results, err := ScanPorts(ctx, "127.0.0.1", []int{openPort, closedPort}, 1*time.Second)
	if err != nil {
		t.Fatalf("ScanPorts error: %v", err)
	}

	states := make(map[int]string)
	for _, r := range results {
		states[r.Port] = r.State
	}
	if states[openPort] != "open" {
		t.Errorf("expected port %d open, got %q", openPort, states[openPort])
	}
	if states[closedPort] == "open" {
		t.Errorf("expected port %d not open, got %q", closedPort, states[closedPort])
	}
}
