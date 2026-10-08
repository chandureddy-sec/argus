package report

import (
	"fmt"
	"strings"

	"reconx/pkg/models"
)

// writeGeoMarkdown lists where the scan's IPs are geolocated.
func writeGeoMarkdown(sb *strings.Builder, pi *models.PassiveIntel) {
	pts, missing := GeoPoints(pi)
	if len(pts) == 0 {
		return
	}
	sb.WriteString("## Geographic Distribution\n\n")
	sb.WriteString("_ip-api.com estimates — often a city or country centroid; anycast/CDN IPs show one point of presence._\n\n")
	sb.WriteString("| Location | Lat, Lon | IPs | Hosts | Providers |\n| :--- | :--- | :--- | :--- | :--- |\n")
	for _, p := range pts {
		fmt.Fprintf(sb, "| %s | %.2f, %.2f | %s | %d | %s |\n", p.Place, p.Lat, p.Lon, strings.Join(p.IPs, ", "), p.Hosts, dash(strings.Join(p.Providers, ", ")))
	}
	if missing > 0 {
		fmt.Fprintf(sb, "\n%d IP(s) had no coordinates.\n", missing)
	}
	sb.WriteString("\n")
}
