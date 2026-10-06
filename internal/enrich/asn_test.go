package enrich

import (
	"testing"
)

func TestDetectCloudProvider(t *testing.T) {
	tests := []struct {
		name     string
		isp      string
		org      string
		as       string
		expected string
	}{
		{"Cloudflare", "Cloudflare, Inc.", "Cloudflare, Inc.", "AS13335 CLOUDFLARENET", "Cloudflare (CDN/Proxy)"},
		{"AWS", "Amazon.com, Inc.", "AWS", "AS16509 AMAZON-02", "Amazon Web Services (AWS)"},
		{"Google", "Google LLC", "Google LLC", "AS15169 GOOGLE", "Google Cloud Platform (GCP)"},
		{"Azure", "Microsoft Corporation", "Microsoft Azure", "AS8075 MICROSOFT-CORP-AS", "Microsoft Azure"},
		{"Akamai", "Akamai Technologies", "Akamai", "AS20940", "Akamai (CDN/WAF)"},
		{"DigitalOcean", "DigitalOcean, LLC", "DigitalOcean", "AS14061", "DigitalOcean"},
		{"Fallback Org", "Some ISP", "Custom Corp", "AS99999", "Custom Corp"},
		{"Unknown", "", "", "", "Unknown / On-Premise"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := detectCloudProvider(tc.isp, tc.org, tc.as)
			if got != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}
