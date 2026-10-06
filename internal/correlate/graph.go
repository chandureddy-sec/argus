package correlate

import (
	"sort"

	"reconx/internal/enrich"
	"reconx/pkg/models"
)

// BuildGraph assembles normalized assets, resolved IP addresses, and IP intelligence into a connected graph.
func BuildGraph(
	targetDomain string,
	normalizedAssets []models.Asset,
	hostIPs map[string][]string,
	ipIntel map[string]enrich.IPIntelligence,
) *models.Graph {
	graph := &models.Graph{
		TargetDomain: targetDomain,
		TotalAssets:  len(normalizedAssets),
		Nodes:        make([]models.CorrelatedAsset, 0, len(normalizedAssets)),
	}

	liveCount := 0

	for _, asset := range normalizedAssets {
		ips := hostIPs[asset.Asset]
		isAlive := len(ips) > 0

		node := models.CorrelatedAsset{
			Hostname:    asset.Asset,
			Sources:     asset.Sources,
			Confidence:  asset.Confidence,
			IsAlive:     isAlive,
			ResolvedIPs: ips,
		}

		if isAlive {
			liveCount++
			// Attach metadata from the first public IP
			for _, ip := range ips {
				if intel, ok := ipIntel[ip]; ok {
					if intel.ASN != "" && node.ASN == "" {
						node.ASN = intel.ASN
					}
					if intel.Organization != "" && node.Organization == "" {
						node.Organization = intel.Organization
					}
					if intel.ISP != "" && node.ISP == "" {
						node.ISP = intel.ISP
					}
					if intel.CloudProvider != "" && node.CloudProvider == "" {
						node.CloudProvider = intel.CloudProvider
					}
					if intel.Country != "" && node.Country == "" {
						node.Country = intel.Country
					}
				}
			}
		}

		if node.CloudProvider == "" && isAlive {
			node.CloudProvider = "Unclassified"
		}

		graph.Nodes = append(graph.Nodes, node)
	}

	graph.LiveAssets = liveCount

	// Sort nodes: Live assets first, then alphabetically
	sort.Slice(graph.Nodes, func(i, j int) bool {
		if graph.Nodes[i].IsAlive != graph.Nodes[j].IsAlive {
			return graph.Nodes[i].IsAlive
		}
		return graph.Nodes[i].Hostname < graph.Nodes[j].Hostname
	})

	return graph
}
