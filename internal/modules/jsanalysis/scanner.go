package jsanalysis

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"reconx/pkg/models"
)

var patterns = map[string]*regexp.Regexp{
	"AWS Access Key":     regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	"Generic API Key":    regexp.MustCompile(`(?i)(api_key|apikey|api-key)\s*[:=]\s*['"][^'"]{8,}`),
	"JWT Token":          regexp.MustCompile(`eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+`),
	"Private Key Header": regexp.MustCompile(`-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----`),
	"Generic Secret":     regexp.MustCompile(`(?i)(secret|password|passwd|token)\s*[:=]\s*['"][^'"]{8,}`),
	"Google API Key":     regexp.MustCompile(`AIza[0-9A-Za-z-_]{35}`),
}

// AnalyzeScripts fetches scripts and scans them for exposed secrets or issues.
func AnalyzeScripts(ctx context.Context, scriptURLs []string, baseDomain string) []models.JSFinding {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	var findings []models.JSFinding

	for _, scriptURL := range scriptURLs {
		isThirdParty := !strings.Contains(scriptURL, baseDomain)

		req, err := http.NewRequestWithContext(ctx, "GET", scriptURL, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			continue
		}

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		content := string(bodyBytes)

		var matchedSecrets []string
		for name, regex := range patterns {
			if regex.MatchString(content) {
				matchedSecrets = append(matchedSecrets, name)
			}
		}

		sourceMapURL := ""
		sourceMapReachable := false
		if strings.Contains(content, "//# sourceMappingURL=") {
			sourceMapURL = scriptURL + ".map"
			mapReq, err := http.NewRequestWithContext(ctx, "GET", sourceMapURL, nil)
			if err == nil {
				mapResp, err := client.Do(mapReq)
				if err == nil {
					mapResp.Body.Close()
					if mapResp.StatusCode == http.StatusOK {
						sourceMapReachable = true
					}
				}
			}
		}

		if len(matchedSecrets) > 0 || sourceMapURL != "" {
			findings = append(findings, models.JSFinding{
				ScriptURL:          scriptURL,
				IsThirdParty:       isThirdParty,
				Secrets:            matchedSecrets,
				SourceMapURL:       sourceMapURL,
				SourceMapReachable: sourceMapReachable,
			})
		}
	}

	return findings
}
