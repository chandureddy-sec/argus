package intel

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"reconx/internal/providers/crtsh"
	"reconx/pkg/models"
)

// maxListedCerts caps how many certificates are stored individually; the
// summary still counts every certificate. Large domains log thousands.
const maxListedCerts = 300

var certIndicatorWords = []string{"dev", "development", "test", "testing", "staging", "stage", "qa", "uat",
	"admin", "api", "vpn", "internal", "old", "legacy", "beta", "sandbox"}

// crt.sh timestamps have no zone and are UTC.
func parseCrtTime(s string) time.Time {
	for _, layout := range []string{"2006-01-02T15:04:05.999", "2006-01-02T15:04:05", time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// issuerParts extracts a display name and the organization from an X.500
// issuer string such as "C=US, O=Let's Encrypt, CN=R3".
func issuerParts(dn string) (display, org string) {
	var cn string
	for _, part := range strings.Split(dn, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch strings.ToUpper(strings.TrimSpace(k)) {
		case "O":
			org = strings.Trim(strings.TrimSpace(v), `"`)
		case "CN":
			cn = strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	switch {
	case org != "" && cn != "":
		display = org + " (" + cn + ")"
	case org != "":
		display = org
	case cn != "":
		display = cn
	default:
		display = dn
	}
	return display, org
}

func expiryStatus(notAfter, now time.Time) string {
	d := notAfter.Sub(now)
	switch {
	case d < 0:
		return "expired"
	case d < 7*24*time.Hour:
		return "lt7"
	case d < 14*24*time.Hour:
		return "lt14"
	case d < 30*24*time.Hour:
		return "lt30"
	default:
		return "ok"
	}
}

// certIndicators returns the indicator words appearing in a certificate's
// names. These mark hostnames worth reviewing, not vulnerabilities.
func certIndicators(names []string, domain string) []string {
	var out []string
	for _, n := range names {
		for _, l := range labelsOf(strings.TrimPrefix(n, "*."), domain) {
			for _, w := range certIndicatorWords {
				if l == w && !contains(out, w) {
					out = append(out, w)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// BuildCertificates turns crt.sh entries into deduplicated certificates (a
// precertificate and its final certificate share issuer + serial), a health
// summary over all of them, and per-host certificate counts.
func BuildCertificates(entries []crtsh.Entry, domain string, now time.Time) ([]models.CertInfo, models.CertSummary, map[string]int) {
	domain = strings.ToLower(domain)
	byKey := map[string]*models.CertInfo{}
	var order []string

	for _, e := range entries {
		key := e.IssuerName + "|" + e.SerialNumber
		if e.SerialNumber == "" {
			key = e.IssuerName + "|id" + strconv.FormatInt(e.ID, 10)
		}
		logged := parseCrtTime(e.EntryTimestamp)
		if c, ok := byKey[key]; ok {
			if !logged.IsZero() && (c.LoggedAt.IsZero() || logged.Before(c.LoggedAt)) {
				c.LoggedAt = logged
			}
			continue
		}
		nb, na := parseCrtTime(e.NotBefore), parseCrtTime(e.NotAfter)
		issuer, org := issuerParts(e.IssuerName)
		var sans []string
		wildcard := false
		for _, n := range e.Names() {
			if strings.HasPrefix(n, "*.") {
				wildcard = true
			}
			sans = append(sans, n)
		}
		sort.Strings(sans)
		c := &models.CertInfo{
			ID:         e.ID,
			Serial:     e.SerialNumber,
			Issuer:     issuer,
			IssuerOrg:  org,
			CommonName: strings.ToLower(e.CommonName),
			SANs:       sans,
			NotBefore:  nb,
			NotAfter:   na,
			Wildcard:   wildcard,
			LoggedAt:   logged,
			Indicators: certIndicators(sans, domain),
			Source:     "crt.sh",
		}
		if !nb.IsZero() && !na.IsZero() {
			c.ValidityDays = int(na.Sub(nb).Hours() / 24)
		}
		c.ExpiryStatus = expiryStatus(na, now)
		byKey[key] = c
		order = append(order, key)
	}

	certs := make([]models.CertInfo, 0, len(order))
	for _, k := range order {
		certs = append(certs, *byKey[k])
	}
	// Newest first.
	sort.Slice(certs, func(i, j int) bool { return certs[i].NotBefore.After(certs[j].NotBefore) })

	sum := models.CertSummary{Total: len(certs)}
	issuers := map[string]int{}
	hostCerts := map[string]int{}
	var oldest time.Time
	for _, c := range certs {
		switch c.ExpiryStatus {
		case "expired":
			sum.Expired++
		case "lt7":
			sum.Lt7++
			sum.Valid++
		case "lt14":
			sum.Lt14++
			sum.Valid++
		case "lt30":
			sum.Lt30++
			sum.Valid++
		default:
			sum.Valid++
		}
		if c.Wildcard {
			sum.Wildcard++
		}
		issuers[c.IssuerOrg]++
		if !c.NotBefore.IsZero() && (oldest.IsZero() || c.NotBefore.Before(oldest)) {
			oldest = c.NotBefore
		}
		for _, n := range c.SANs {
			h := strings.TrimPrefix(n, "*.")
			if h == domain || strings.HasSuffix(h, "."+domain) {
				hostCerts[h]++
			}
		}
	}
	for name, n := range issuers {
		if name == "" {
			name = "(unknown)"
		}
		sum.Issuers = append(sum.Issuers, models.Count{Name: name, Count: n})
	}
	sortCounts(sum.Issuers)
	if !oldest.IsZero() {
		sum.OldestSeen = oldest.Format("2006-01-02")
	}

	if len(certs) > maxListedCerts {
		certs = certs[:maxListedCerts]
	}
	sum.Listed = len(certs)
	return certs, sum, hostCerts
}

func sortCounts(c []models.Count) {
	sort.Slice(c, func(i, j int) bool {
		if c[i].Count != c[j].Count {
			return c[i].Count > c[j].Count
		}
		return c[i].Name < c[j].Name
	})
}
