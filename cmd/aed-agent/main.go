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
	"strings"
	"time"

	"reconx/internal/aed/agent"
)


func firstExisting(paths ...string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if len(paths) > 0 {
		return paths[0]
	}
	return ""
}

func readKVConf(path string) map[string]string {
	out := make(map[string]string)
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			out[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return out
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	// `aed-agent install …` enrols this host; with no subcommand it runs the
	// collection/heartbeat loop.
	if len(os.Args) > 1 && os.Args[1] == "install" {
		runInstall(os.Args[2:])
		return
	}
	gateway := flag.String("gateway", envOr("AED_GATEWAY_URL", ""), "AED gateway base URL, e.g. https://host:8443")
	agentID := flag.String("agent-id", envOr("AED_AGENT_ID", ""), "this agent's id")
	certFile := flag.String("cert", envOr("AED_CERT", "/var/lib/aed/agent.crt"), "agent client certificate (PEM)")
	keyFile := flag.String("key", envOr("AED_KEY", "/var/lib/aed/agent.key"), "agent private key (PEM)")
	caFile := flag.String("ca", envOr("AED_CA", "/var/lib/aed/ca.crt"), "gateway CA certificate (PEM)")
	interval := flag.Duration("interval", 30*time.Second, "heartbeat interval")
	version := flag.String("version", "0.1.0", "agent version string")
	flag.Parse()

	// If flags are not provided, auto-discover from /etc/aed-agent or /var/lib/aed
	confPath := firstExisting("/etc/aed-agent/agent.conf", "/var/lib/aed/agent.conf")
	if confPath != "" {
		kv := readKVConf(confPath)
		if *gateway == "" {
			*gateway = kv["gateway_url"]
		}
		if *agentID == "" {
			*agentID = kv["agent_id"]
		}
	}
	if *certFile == "/var/lib/aed/agent.crt" {
		*certFile = firstExisting("/etc/aed-agent/agent.crt", "/var/lib/aed/agent.crt")
	}
	if *keyFile == "/var/lib/aed/agent.key" {
		*keyFile = firstExisting("/etc/aed-agent/agent.key", "/var/lib/aed/agent.key")
	}
	if *caFile == "/var/lib/aed/ca.crt" {
		*caFile = firstExisting("/etc/aed-agent/ca.crt", "/var/lib/aed/ca.crt")
	}

	if *gateway == "" || *agentID == "" {
		log.Fatal("aed-agent: --gateway and --agent-id are required (or /etc/aed-agent/agent.conf)")
	}
	httpClient, err := agent.MTLSClient(*certFile, *keyFile, *caFile, 10*time.Second)
	if err != nil {
		log.Fatalf("aed-agent: mTLS setup failed: %v", err)
	}
	certBytes, _ := os.ReadFile(*certFile)
	c := agent.New(agent.Config{
		GatewayURL:        *gateway,
		AgentID:           *agentID,
		Version:           *version,
		HeartbeatInterval: *interval,
		CertPEM:           certBytes,
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
