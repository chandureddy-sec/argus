package models

import "time"

// NmapResult holds the parsed output of an nmap scan. It is produced only in
// Active mode, behind the authorization confirmation, by driving the real nmap
// binary. Fields mirror what nmap reports; empty ones mean nmap did not return
// that data (often because the scan ran without the privileges it needs).
type NmapResult struct {
	Available   bool          `json:"available"`             // nmap binary was found and ran
	Unavailable string        `json:"unavailable,omitempty"` // why nmap could not run
	Version     string        `json:"version,omitempty"`     // nmap version string
	Command     string        `json:"command,omitempty"`     // the exact argv executed
	Profile     string        `json:"profile,omitempty"`     // quick | aggressive | full | custom
	Privileged  bool          `json:"privileged"`            // nmap ran with raw-packet privileges
	ScanType    string        `json:"scan_type,omitempty"`   // e.g. "connect", "syn"
	StartedAt   time.Time     `json:"started_at,omitempty"`
	ElapsedSec  float64       `json:"elapsed_sec,omitempty"`
	HostState   string        `json:"host_state,omitempty"` // up | down
	Hostnames   []string      `json:"hostnames,omitempty"`
	Addresses   []NmapAddr    `json:"addresses,omitempty"`
	Ports       []NmapPort    `json:"ports,omitempty"`
	OSMatches   []NmapOSMatch `json:"os_matches,omitempty"`
	HostScripts []NmapScript  `json:"host_scripts,omitempty"`
	Warnings    []string      `json:"warnings,omitempty"` // nmap stderr notices (e.g. privilege fallbacks)
	Summary     string        `json:"summary,omitempty"`  // nmap's own run summary line
}

// NmapAddr is one address nmap reported for the host.
type NmapAddr struct {
	Addr   string `json:"addr"`
	Type   string `json:"type"`             // ipv4 | ipv6 | mac
	Vendor string `json:"vendor,omitempty"` // MAC vendor, when known
}

// NmapPort is a single scanned port with its service and script output.
type NmapPort struct {
	Port       int          `json:"port"`
	Protocol   string       `json:"protocol"` // tcp | udp
	State      string       `json:"state"`    // open | closed | filtered | open|filtered
	Reason     string       `json:"reason,omitempty"`
	Service    string       `json:"service,omitempty"`
	Product    string       `json:"product,omitempty"`
	Version    string       `json:"version,omitempty"`
	ExtraInfo  string       `json:"extra_info,omitempty"`
	Tunnel     string       `json:"tunnel,omitempty"` // e.g. "ssl"
	CPE        []string     `json:"cpe,omitempty"`
	Confidence int          `json:"confidence,omitempty"` // service detection confidence 0-10
	Scripts    []NmapScript `json:"scripts,omitempty"`
}

// VersionString renders product/version/extrainfo the way nmap displays them.
func (p NmapPort) VersionString() string {
	out := p.Product
	if p.Version != "" {
		if out != "" {
			out += " "
		}
		out += p.Version
	}
	if p.ExtraInfo != "" {
		out += " (" + p.ExtraInfo + ")"
	}
	return out
}

// NmapOSMatch is one OS fingerprint guess.
type NmapOSMatch struct {
	Name     string `json:"name"`
	Accuracy int    `json:"accuracy"` // percentage
	Family   string `json:"family,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
}

// NmapScript is the output of one NSE script, on a port or on the host.
type NmapScript struct {
	ID     string `json:"id"`
	Output string `json:"output"`
}

// OpenPortsLegacy projects nmap ports onto the existing PortResult model so the
// current report sections can show nmap's richer open-port data.
func (r *NmapResult) OpenPortsLegacy() []PortResult {
	out := make([]PortResult, 0, len(r.Ports))
	for _, p := range r.Ports {
		if p.State != "open" {
			continue
		}
		out = append(out, PortResult{
			Port:     p.Port,
			Protocol: p.Protocol,
			State:    p.State,
			Service:  p.Service,
			Banner:   p.VersionString(),
		})
	}
	return out
}
