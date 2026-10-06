package techdetect

import (
	"strings"

	"reconx/pkg/models"
)

// Detect analyzes headers and cookies to determine the tech stack.
func Detect(probe *models.HTTPProbeResult) *models.TechStack {
	stack := &models.TechStack{}
	if probe == nil {
		return stack
	}

	// Web Server Detection
	serverLower := strings.ToLower(probe.Server)
	if strings.Contains(serverLower, "nginx") {
		stack.WebServer = "nginx"
	} else if strings.Contains(serverLower, "apache") {
		stack.WebServer = "Apache"
	} else if strings.Contains(serverLower, "iis") {
		stack.WebServer = "IIS"
	} else if strings.Contains(serverLower, "caddy") {
		stack.WebServer = "Caddy"
	} else if probe.Server != "" {
		stack.WebServer = probe.Server
	}

	// Language / Framework Detection
	poweredByLower := strings.ToLower(probe.PoweredBy)
	if strings.Contains(poweredByLower, "php") {
		stack.Language = "PHP"
	} else if strings.Contains(poweredByLower, "asp.net") {
		stack.Language = "ASP.NET"
		stack.Framework = "ASP.NET"
	} else if probe.PoweredBy != "" {
		stack.Language = probe.PoweredBy
	}

	// CDN Detection
	headersLower := make(map[string]string)
	for k, v := range probe.Headers {
		headersLower[strings.ToLower(k)] = strings.ToLower(v)
	}

	if _, ok := headersLower["cf-ray"]; ok {
		stack.CDN = "Cloudflare"
	} else if _, ok := headersLower["x-amz-cf-id"]; ok {
		stack.CDN = "AWS CloudFront"
	} else if _, ok := headersLower["x-served-by"]; ok {
		if strings.Contains(headersLower["x-served-by"], "fastly") {
			stack.CDN = "Fastly"
		}
	}
	for k := range headersLower {
		if strings.HasPrefix(k, "x-akamai-") {
			stack.CDN = "Akamai"
			break
		}
	}

	// WAF Detection
	if stack.CDN == "Cloudflare" {
		stack.WAF = "Cloudflare"
	} else if _, ok := headersLower["x-sucuri-id"]; ok {
		stack.WAF = "Sucuri"
	} else if strings.Contains(serverLower, "mod_security") || strings.Contains(serverLower, "modsecurity") {
		stack.WAF = "ModSecurity"
	} else {
		for _, cookie := range probe.Cookies {
			if strings.Contains(strings.ToLower(cookie.Name), "incap_ses") || strings.Contains(strings.ToLower(cookie.Name), "visid_incap") {
				stack.WAF = "Imperva / Incapsula"
				break
			}
			if strings.Contains(strings.ToLower(cookie.Name), "akamai") {
				stack.WAF = "Akamai"
				break
			}
		}
	}

	// CMS Detection
	if _, ok := headersLower["x-drupal-cache"]; ok || strings.Contains(headersLower["x-generator"], "drupal") {
		stack.CMS = "Drupal"
	} else {
		for _, cookie := range probe.Cookies {
			if strings.HasPrefix(strings.ToLower(cookie.Name), "wp-") || strings.HasPrefix(strings.ToLower(cookie.Name), "wordpress_") {
				stack.CMS = "WordPress"
				break
			}
		}
	}

	return stack
}
