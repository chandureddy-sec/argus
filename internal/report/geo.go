package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"math"
	"sort"
	"strings"

	"reconx/pkg/models"
)

// WorldLandPath is SVG path data for the world's land masses in an
// equirectangular projection on a 1000×500 canvas (x = lon, y = lat). It is
// generated from Natural Earth 1:110m land via world-atlas; see
// assets/NOTICE.md. Embedded so reports and the dashboard work offline.
//
//go:embed assets/world_land.path
var WorldLandPath string

// GeoPoint is one map marker: every IP geolocated to (roughly) the same spot.
type GeoPoint struct {
	Lat       float64  `json:"lat"`
	Lon       float64  `json:"lon"`
	X         float64  `json:"x"` // projected onto the 1000×500 canvas
	Y         float64  `json:"y"`
	Place     string   `json:"place"`
	Country   string   `json:"country,omitempty"`
	IPs       []string `json:"ips"`
	Hosts     int      `json:"hosts"`
	Providers []string `json:"providers,omitempty"`
	Exposed   int      `json:"exposed,omitempty"` // IPs with Shodan open ports
	KEV       bool     `json:"kev,omitempty"`     // any IP here has a KEV-listed CVE
}

// Project maps a coordinate onto the 1000×500 equirectangular canvas.
func Project(lat, lon float64) (x, y float64) {
	return (lon + 180) / 360 * 1000, (90 - lat) / 180 * 500
}

// GeoPoints groups the scan's geolocated IPs into map markers, merging IPs
// within ~0.5° of each other (ip-api often returns a shared city centroid).
// Points are ordered by IP count, largest first. IPs without coordinates are
// counted in the second return value.
func GeoPoints(pi *models.PassiveIntel) ([]GeoPoint, int) {
	if pi == nil {
		return nil, 0
	}
	type acc struct {
		GeoPoint
		hosts map[string]bool
		provs map[string]bool
	}
	byKey := map[string]*acc{}
	missing := 0
	for _, ip := range pi.IPs {
		if ip.Lat == 0 && ip.Lon == 0 {
			missing++
			continue
		}
		key := fmt.Sprintf("%.0f,%.0f", ip.Lat*2, ip.Lon*2)
		a := byKey[key]
		if a == nil {
			a = &acc{GeoPoint: GeoPoint{Lat: ip.Lat, Lon: ip.Lon, Country: ip.Country, Place: place(ip)},
				hosts: map[string]bool{}, provs: map[string]bool{}}
			byKey[key] = a
		}
		a.IPs = append(a.IPs, ip.IP)
		for _, h := range ip.Hostnames {
			a.hosts[h] = true
		}
		if p := firstNonBlank(ip.Provider, ip.Organization); p != "" {
			a.provs[p] = true
		}
		if ip.Exposure != nil && len(ip.Exposure.Ports) > 0 {
			a.Exposed++
		}
		if ip.Exposure != nil {
			for _, v := range ip.Exposure.Vulns {
				if v.KEV {
					a.KEV = true
				}
			}
		}
	}
	out := make([]GeoPoint, 0, len(byKey))
	for _, a := range byKey {
		p := a.GeoPoint
		p.X, p.Y = Project(p.Lat, p.Lon)
		p.X, p.Y = math.Round(p.X*10)/10, math.Round(p.Y*10)/10
		p.Hosts = len(a.hosts)
		for name := range a.provs {
			p.Providers = append(p.Providers, name)
		}
		sort.Strings(p.Providers)
		sort.Strings(p.IPs)
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].IPs) != len(out[j].IPs) {
			return len(out[i].IPs) > len(out[j].IPs)
		}
		return out[i].Place < out[j].Place
	})
	return out, missing
}

func place(ip models.IPInfo) string {
	parts := []string{}
	for _, s := range []string{ip.City, ip.Region, ip.Country} {
		if s != "" && (len(parts) == 0 || parts[len(parts)-1] != s) {
			parts = append(parts, s)
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("%.2f, %.2f", ip.Lat, ip.Lon)
	}
	return strings.Join(parts, ", ")
}

func firstNonBlank(s ...string) string {
	for _, v := range s {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// geoMapSVG renders the static map used in the HTML report: land masses plus
// one circle per GeoPoint, sized by IP count. Returns "" when no IP has
// coordinates, so the template can skip the section.
func geoMapSVG(pi *models.PassiveIntel) template.HTML {
	pts, missing := GeoPoints(pi)
	if len(pts) == 0 {
		return ""
	}
	var b strings.Builder
	// Crop the poles: y 30..440 covers ~84°N to ~68°S.
	b.WriteString(`<svg viewBox="0 30 1000 410" role="img" aria-label="Map of IP locations" style="width:100%;height:auto;background:#0b1220;border:1px solid var(--border);border-radius:10px">`)
	fmt.Fprintf(&b, `<path d="%s" fill="#243042"/>`, template.HTMLEscapeString(WorldLandPath))
	for i := len(pts) - 1; i >= 0; i-- { // largest drawn last, on top
		p := pts[i]
		r := 3.5 + 2.5*math.Sqrt(float64(len(p.IPs)))
		fill := "#D7FFE0"
		if p.KEV {
			fill = "#f87171"
		} else if p.Exposed > 0 {
			fill = "#fb923c"
		}
		fmt.Fprintf(&b, `<circle cx="%.1f" cy="%.1f" r="%.1f" fill="%s" fill-opacity="0.75" stroke="#050505" stroke-width="0.8"><title>%s — %d IP(s), %d host(s)%s</title></circle>`,
			p.X, p.Y, r, fill, template.HTMLEscapeString(p.Place), len(p.IPs), p.Hosts, providerSuffix(p.Providers))
	}
	b.WriteString(`</svg>`)
	b.WriteString(`<p><small>Circle size = number of IPs. <span style="color:#D7FFE0">●</span> no reported exposure · <span style="color:#fb923c">●</span> open ports in Shodan · <span style="color:#f87171">●</span> a CISA KEV-listed CVE reported. Locations are ip-api.com estimates (often a city or country centroid; anycast/CDN IPs show one point of presence)`)
	if missing > 0 {
		fmt.Fprintf(&b, `; %d IP(s) had no coordinates`, missing)
	}
	b.WriteString(`.</small></p><table><thead><tr><th>Location</th><th>IPs</th><th>Hosts</th><th>Providers</th></tr></thead><tbody>`)
	for _, p := range pts {
		fmt.Fprintf(&b, `<tr><td>%s</td><td><small>%s</small></td><td>%d</td><td><small>%s</small></td></tr>`,
			template.HTMLEscapeString(p.Place), template.HTMLEscapeString(strings.Join(p.IPs, ", ")), p.Hosts, template.HTMLEscapeString(strings.Join(p.Providers, ", ")))
	}
	b.WriteString(`</tbody></table>`)
	return template.HTML(b.String())
}

func providerSuffix(p []string) string {
	if len(p) == 0 {
		return ""
	}
	return " · " + strings.Join(p, ", ")
}
