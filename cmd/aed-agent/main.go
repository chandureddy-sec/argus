// Command aed-agent is the AED lab endpoint agent (collection only; no actions
// on the host). Slice 3: enrolls out-of-band, then heartbeats to the gateway
// over mTLS. Lab use only.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"reconx/internal/aed/agent"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	gateway := flag.String("gateway", envOr("AED_GATEWAY_URL", ""), "AED gateway base URL, e.g. https://host:8443")
	agentID := flag.String("agent-id", envOr("AED_AGENT_ID", ""), "this agent's id")
	certFile := flag.String("cert", envOr("AED_CERT", "/var/lib/aed/agent.crt"), "agent client certificate (PEM)")
	keyFile := flag.String("key", envOr("AED_KEY", "/var/lib/aed/agent.key"), "agent private key (PEM)")
	caFile := flag.String("ca", envOr("AED_CA", "/var/lib/aed/ca.crt"), "gateway CA certificate (PEM)")
	interval := flag.Duration("interval", 30*time.Second, "heartbeat interval")
	version := flag.String("version", "0.1.0", "agent version string")
	flag.Parse()

	if *gateway == "" || *agentID == "" {
		log.Fatal("aed-agent: --gateway and --agent-id are required")
	}
	httpClient, err := agent.MTLSClient(*certFile, *keyFile, *caFile, 10*time.Second)
	if err != nil {
		log.Fatalf("aed-agent: mTLS setup failed: %v", err)
	}
	c := agent.New(agent.Config{
		GatewayURL:        *gateway,
		AgentID:           *agentID,
		Version:           *version,
		HeartbeatInterval: *interval,
	}, httpClient)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	q := agent.NewQueue(10000)
	q.Push(agent.BuildInventory(*agentID, *version)) // report inventory on start
	startCollectors(ctx, c, q)                       // Linux: follow sshd failures
	go c.ShipLoop(ctx, q, 200, 15*time.Second)       // drain telemetry to the gateway
	go c.Run(ctx)                                    // heartbeats

	log.Printf("aed-agent: started (gateway %s, heartbeat %s)", *gateway, *interval)
	<-ctx.Done()
	log.Print("aed-agent: shutting down")
}
