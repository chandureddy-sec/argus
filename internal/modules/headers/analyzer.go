package headers

import (
	"strings"

	"reconx/pkg/models"
)

// AnalyzeHeaders takes a map of HTTP response headers and analyzes them for security misconfigurations.
func AnalyzeHeaders(headers map[string]string) ([]models.HeaderFinding, []models.Finding) {
	normalized := make(map[string]string)
	for k, v := range headers {
		normalized[strings.ToLower(k)] = v
	}

	var headerFindings []models.HeaderFinding
	var generalFindings []models.Finding

	// Content-Security-Policy
	if val, ok := normalized["content-security-policy"]; !ok {
		headerFindings = append(headerFindings, models.HeaderFinding{
			Header:   "Content-Security-Policy",
			Present:  false,
			Severity: "HIGH",
			Note:     "Missing Content-Security-Policy header",
		})
	} else {
		if strings.Contains(val, "'unsafe-inline'") {
			headerFindings = append(headerFindings, models.HeaderFinding{
				Header:   "Content-Security-Policy",
				Present:  true,
				Value:    val,
				Severity: "MEDIUM",
				Note:     "CSP contains 'unsafe-inline'",
			})
		} else if strings.Contains(val, "*") {
			headerFindings = append(headerFindings, models.HeaderFinding{
				Header:   "Content-Security-Policy",
				Present:  true,
				Value:    val,
				Severity: "MEDIUM",
				Note:     "CSP contains '*' wildcard",
			})
		} else {
			headerFindings = append(headerFindings, models.HeaderFinding{
				Header:   "Content-Security-Policy",
				Present:  true,
				Value:    val,
				Severity: "INFO",
				Note:     "Content-Security-Policy is present and good",
			})
		}
	}

	// X-Frame-Options
	if val, ok := normalized["x-frame-options"]; !ok {
		headerFindings = append(headerFindings, models.HeaderFinding{
			Header:   "X-Frame-Options",
			Present:  false,
			Severity: "MEDIUM",
			Note:     "Missing X-Frame-Options header",
		})
	} else {
		headerFindings = append(headerFindings, models.HeaderFinding{
			Header:   "X-Frame-Options",
			Present:  true,
			Value:    val,
			Severity: "INFO",
			Note:     "X-Frame-Options is present",
		})
	}

	// X-Content-Type-Options
	if val, ok := normalized["x-content-type-options"]; !ok || strings.ToLower(val) != "nosniff" {
		headerFindings = append(headerFindings, models.HeaderFinding{
			Header:   "X-Content-Type-Options",
			Present:  ok,
			Value:    val,
			Severity: "LOW",
			Note:     "Missing or incorrect X-Content-Type-Options header",
		})
	} else {
		headerFindings = append(headerFindings, models.HeaderFinding{
			Header:   "X-Content-Type-Options",
			Present:  true,
			Value:    val,
			Severity: "INFO",
			Note:     "X-Content-Type-Options is present",
		})
	}

	// Referrer-Policy
	if val, ok := normalized["referrer-policy"]; !ok {
		headerFindings = append(headerFindings, models.HeaderFinding{
			Header:   "Referrer-Policy",
			Present:  false,
			Severity: "LOW",
			Note:     "Missing Referrer-Policy header",
		})
	} else {
		headerFindings = append(headerFindings, models.HeaderFinding{
			Header:   "Referrer-Policy",
			Present:  true,
			Value:    val,
			Severity: "INFO",
			Note:     "Referrer-Policy is present",
		})
	}

	// Permissions-Policy
	if val, ok := normalized["permissions-policy"]; !ok {
		headerFindings = append(headerFindings, models.HeaderFinding{
			Header:   "Permissions-Policy",
			Present:  false,
			Severity: "LOW",
			Note:     "Missing Permissions-Policy header",
		})
	} else {
		headerFindings = append(headerFindings, models.HeaderFinding{
			Header:   "Permissions-Policy",
			Present:  true,
			Value:    val,
			Severity: "INFO",
			Note:     "Permissions-Policy is present",
		})
	}

	// Strict-Transport-Security
	if val, ok := normalized["strict-transport-security"]; !ok {
		headerFindings = append(headerFindings, models.HeaderFinding{
			Header:   "Strict-Transport-Security",
			Present:  false,
			Severity: "HIGH",
			Note:     "Missing Strict-Transport-Security header",
		})
	} else {
		lowered := strings.ToLower(val)
		if !strings.Contains(lowered, "includesubdomains") {
			headerFindings = append(headerFindings, models.HeaderFinding{
				Header:   "Strict-Transport-Security",
				Present:  true,
				Value:    val,
				Severity: "LOW",
				Note:     "HSTS missing includeSubDomains",
			})
		} else if !strings.Contains(lowered, "preload") {
			headerFindings = append(headerFindings, models.HeaderFinding{
				Header:   "Strict-Transport-Security",
				Present:  true,
				Value:    val,
				Severity: "INFO",
				Note:     "HSTS missing preload",
			})
		} else {
			headerFindings = append(headerFindings, models.HeaderFinding{
				Header:   "Strict-Transport-Security",
				Present:  true,
				Value:    val,
				Severity: "INFO",
				Note:     "Strict-Transport-Security is present and good",
			})
		}
	}

	// X-XSS-Protection
	if val, ok := normalized["x-xss-protection"]; ok {
		headerFindings = append(headerFindings, models.HeaderFinding{
			Header:   "X-XSS-Protection",
			Present:  true,
			Value:    val,
			Severity: "INFO",
			Note:     "X-XSS-Protection is present (deprecated)",
		})
	} else {
		headerFindings = append(headerFindings, models.HeaderFinding{
			Header:   "X-XSS-Protection",
			Present:  false,
			Severity: "INFO",
			Note:     "X-XSS-Protection is absent",
		})
	}

	for _, hf := range headerFindings {
		if hf.Severity == "HIGH" || hf.Severity == "MEDIUM" {
			generalFindings = append(generalFindings, models.Finding{
				Category:    "Security Headers",
				Title:       hf.Header + " Issue",
				Description: hf.Note,
				Severity:    hf.Severity,
			})
		}
	}

	return headerFindings, generalFindings
}
