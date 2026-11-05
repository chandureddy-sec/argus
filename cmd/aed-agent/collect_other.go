//go:build !linux

package main

import (
	"context"
	"log"

	"reconx/internal/aed/agent"
)

// startCollectors (non-Linux) is a no-op: journald telemetry is Linux-only.
func startCollectors(_ context.Context, _ *agent.Client, _ *agent.Queue) {
	log.Print("aed-agent: journald telemetry is Linux-only; running heartbeat only on this OS")
}
