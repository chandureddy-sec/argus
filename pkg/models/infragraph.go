package models

// Infrastructure-graph node kinds.
const (
	NodeDomain   = "domain"   // the scanned apex domain
	NodeHost     = "host"     // a discovered subdomain
	NodeCNAME    = "cname"    // an external CNAME target
	NodeIP       = "ip"       // an IPv4/IPv6 address
	NodeASN      = "asn"      // the autonomous system announcing an IP
	NodeProvider = "provider" // an inferred cloud / CDN / hosting provider
	NodeNS       = "ns"       // an authoritative nameserver
	NodeMX       = "mx"       // a mail exchanger
)

// InfraGraph is the scan's infrastructure as nodes and edges: which hosts
// resolve where, who announces those IPs, and which providers sit behind
// them. It is derived entirely from PassiveIntel, so it carries the same
// evidence levels (edges say whether they were observed or inferred).
type InfraGraph struct {
	Target    string      `json:"target"`
	Nodes     []GraphNode `json:"nodes"`
	Edges     []GraphEdge `json:"edges"`
	Truncated bool        `json:"truncated,omitempty"` // hosts were dropped to respect the node cap
	Omitted   int         `json:"omitted_hosts,omitempty"`
}

// GraphNode is one entity in the infrastructure graph.
type GraphNode struct {
	ID     string   `json:"id"` // "<kind>:<label>", unique
	Kind   string   `json:"kind"`
	Label  string   `json:"label"`
	Detail string   `json:"detail,omitempty"` // tooltip text: org, country, role…
	Flags  []string `json:"flags,omitempty"`  // high-interest, new, exposed, kev, dangling, not-resolving
	Weight int      `json:"weight"`           // hosts behind this node (sizes the marker)
}

// GraphEdge links two nodes.
type GraphEdge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Rel      string `json:"rel"`      // subdomain | cname | resolves_to | announced_by | hosted_by | nameserver | mail
	Evidence string `json:"evidence"` // observed | enriched | inferred
}
