package main

import (
	"context"
	"flag"
	"log"
	"os"
	"time"

	"reconx/internal/aed/agent"
)

// runInstall enrols this host: generate a key/CSR, exchange the single-use token
// for a client certificate at the gateway (pinning the CA fingerprint so the
// agent verifies the server before trusting it), and write a protected config.
// Collection-only; it takes no host action beyond writing the config dir.
func runInstall(args []string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	gateway := fs.String("gateway", "", "AED gateway base URL, e.g. https://host:8443")
	caFP := fs.String("ca-fingerprint", "", "pinned CA SHA-256 fingerprint (hex)")
	token := fs.String("token", "", "single-use enrollment token")
	agentID := fs.String("agent-id", "", "agent id (default: hostname)")
	configDir := fs.String("config", "/etc/aed-agent", "config directory")
	_ = fs.Parse(args)

	if *gateway == "" || *caFP == "" || *token == "" {
		log.Fatal("aed-agent install: --gateway, --ca-fingerprint and --token are required")
	}
	id := *agentID
	if id == "" {
		h, err := os.Hostname()
		if err != nil || h == "" {
			log.Fatal("aed-agent install: --agent-id is required (hostname unavailable)")
		}
		id = h
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Pin the CA fingerprint for the enrolment call, before any CA is on disk.
	client := agent.PinnedClient(*caFP, 15*time.Second)
	enrolled, err := agent.Enroll(ctx, client, *gateway, id, *token)
	if err != nil {
		log.Fatalf("aed-agent install: enrolment failed: %v", err)
	}
	if err := agent.WriteConfig(*configDir, enrolled, *gateway, id); err != nil {
		log.Fatalf("aed-agent install: writing config failed: %v", err)
	}
	log.Printf("aed-agent install: enrolled %q; config written to %s", id, *configDir)
}
