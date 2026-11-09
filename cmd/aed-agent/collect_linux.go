//go:build linux

package main

import (
	"context"
	"log"

	"reconx/internal/aed/agent"
)

// startCollectors (Linux) follows sshd failures from the journal into the queue.
func startCollectors(ctx context.Context, c *agent.Client, q *agent.Queue) {
	go func() {
		if err := c.FollowAuthFailures(ctx, q); err != nil && ctx.Err() == nil {
			log.Printf("aed-agent: journal follow ended: %v", err)
		}
	}()
}
