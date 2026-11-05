package agent

import (
	"os"
	"runtime"
	"time"
)

// BuildInventory produces an OCSF Device Inventory event for this host. Only
// non-sensitive, cross-platform facts are collected; command lines and secrets
// are never included.
func BuildInventory(agentID, version string) *Event {
	host, _ := os.Hostname()
	return &Event{
		ClassUID:    ClassDeviceInventory,
		Time:        time.Now().UTC().Format(time.RFC3339),
		AgentID:     agentID,
		OCSFVersion: OCSFVersion,
		Fields: map[string]any{
			"hostname":      host,
			"os":            runtime.GOOS,
			"arch":          runtime.GOARCH,
			"num_cpu":       runtime.NumCPU(),
			"agent_version": version,
		},
	}
}
