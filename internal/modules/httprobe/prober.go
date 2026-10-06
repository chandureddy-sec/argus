package httprobe

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"time"

	"reconx/pkg/models"
)

// Probe probes http:// and https:// and returns the result, preferring https if successful.
func Probe(ctx context.Context, host string) (*models.HTTPProbeResult, error) {
	urls := []string{"https://" + host, "http://" + host}
	var lastErr error
	for _, u := range urls {
		res, err := ProbeURL(ctx, u)
		if err == nil {
			return res, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// ProbeURL executes the probe on a specific URL and tracks redirects manually.
func ProbeURL(ctx context.Context, startURL string) (*models.HTTPProbeResult, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	result := &models.HTTPProbeResult{
		URL:           startURL,
		Headers:       make(map[string]string),
		RedirectChain: []string{},
	}

	currentURL := startURL
	startTime := time.Now()
	maxRedirects := 5
	redirectCount := 0

	var finalResp *http.Response
	var bodyBytes []byte

	for redirectCount < maxRedirects {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, currentURL, nil)
		if err != nil {
			return nil, err
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}

		result.RedirectChain = append(result.RedirectChain, currentURL)

		if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
			loc := resp.Header.Get("Location")
			resp.Body.Close()
			if loc == "" {
				finalResp = resp
				break
			}
			// Handle relative redirects
			if strings.HasPrefix(loc, "/") {
				// Very basic relative URL handling
				parts := strings.SplitN(currentURL, "/", 4)
				if len(parts) >= 3 {
					loc = parts[0] + "//" + parts[2] + loc
				}
			}
			currentURL = loc
			redirectCount++
			continue
		}

		finalResp = resp
		bodyBytes, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		break
	}

	if finalResp == nil {
		return result, nil // Reached max redirects without settling
	}

	result.ResponseTime = time.Since(startTime).Milliseconds()
	result.FinalURL = currentURL
	result.StatusCode = finalResp.StatusCode
	result.Server = finalResp.Header.Get("Server")
	result.PoweredBy = finalResp.Header.Get("X-Powered-By")

	for k, v := range finalResp.Header {
		if len(v) > 0 {
			result.Headers[k] = v[0]
		}
	}

	for _, c := range finalResp.Cookies() {
		result.Cookies = append(result.Cookies, models.CookieInfo{
			Name:     c.Name,
			Domain:   c.Domain,
			Path:     c.Path,
			Secure:   c.Secure,
			HTTPOnly: c.HttpOnly,
			SameSite: func() string {
				if c.SameSite == http.SameSiteLaxMode {
					return "Lax"
				} else if c.SameSite == http.SameSiteStrictMode {
					return "Strict"
				} else if c.SameSite == http.SameSiteNoneMode {
					return "None"
				}
				return ""
			}(),
			Expires: c.Expires.String(),
		})
	}

	// Extract title simple string search
	bodyStr := string(bodyBytes)
	startTitle := strings.Index(strings.ToLower(bodyStr), "<title>")
	if startTitle != -1 {
		endTitle := strings.Index(strings.ToLower(bodyStr[startTitle:]), "</title>")
		if endTitle != -1 {
			result.Title = bodyStr[startTitle+7 : startTitle+endTitle]
		}
	}

	return result, nil
}
