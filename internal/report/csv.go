package report

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"
	"time"

	"reconx/pkg/models"
)

// WriteHostsCSV writes the attack-surface table (one row per subdomain) as
// CSV. Reports without passive intel fall back to the correlation graph.
func WriteHostsCSV(rep *models.ScanReport, w io.Writer) error {
	cw := csv.NewWriter(w)
	header := []string{"hostname", "lifecycle", "dns_status", "recency", "confidence", "confidence_level",
		"sources", "first_seen", "last_seen", "ips", "cnames", "asn", "organization", "country",
		"likely_cloud", "likely_cdn", "likely_role", "indicators", "certificates", "interest", "interest_score"}
	if err := cw.Write(header); err != nil {
		return err
	}
	switch {
	case rep.Intel != nil:
		for _, h := range rep.Intel.Hosts {
			_ = cw.Write([]string{
				h.Hostname, h.Lifecycle, h.DNSStatus, h.Recency, fmt.Sprint(h.Confidence), h.ConfidenceLevel,
				strings.Join(h.Sources, "; "), day(h.FirstSeen), day(h.LastSeen),
				strings.Join(h.IPs, "; "), strings.Join(h.CNAMEs, "; "), h.ASN, h.Organization, h.Country,
				h.Cloud, h.CDN, h.Role, strings.Join(h.Indicators, "; "), fmt.Sprint(h.Certificates),
				h.Interest, fmt.Sprint(h.InterestScore),
			})
		}
	case rep.Correlation != nil:
		for _, n := range rep.Correlation.Nodes {
			status := "no_address"
			if n.IsAlive {
				status = "resolves"
			}
			_ = cw.Write([]string{n.Hostname, "", status, "", fmt.Sprintf("%.0f", n.Confidence*100), "",
				strings.Join(n.Sources, "; "), "", "", strings.Join(n.ResolvedIPs, "; "), "", n.ASN,
				n.Organization, n.Country, n.CloudProvider, "", "", "", "", "", ""})
		}
	}
	cw.Flush()
	return cw.Error()
}

func day(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format("2006-01-02")
}
