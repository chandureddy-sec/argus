package target

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"reconx/pkg/models"
)

var (
	// domainRegex validates standard domain names with at least one dot and valid characters.
	domainRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
)

// Parse takes an arbitrary user input string and parses, cleans, and classifies it into a typed Target.
func Parse(raw string) (*models.Target, error) {
	cleaned := strings.TrimSpace(raw)
	if cleaned == "" {
		return nil, fmt.Errorf("target cannot be empty")
	}

	// Check if input is explicitly tagged as an organization (e.g. "org:Acme Corp")
	if strings.HasPrefix(strings.ToLower(cleaned), "org:") {
		orgVal := strings.TrimSpace(cleaned[4:])
		if orgVal == "" {
			return nil, fmt.Errorf("organization name cannot be empty")
		}
		return &models.Target{
			Original: raw,
			Value:    orgVal,
			Type:     models.TargetTypeOrg,
		}, nil
	}

	// Normalize input if it looks like a URL (e.g. https://example.com/foo:8080)
	candidate := cleaned
	if strings.HasPrefix(candidate, "http://") || strings.HasPrefix(candidate, "https://") {
		u, err := url.Parse(candidate)
		if err == nil && u.Host != "" {
			candidate = u.Host
			// Strip port if present in host (e.g. example.com:8080)
			if host, _, err := net.SplitHostPort(candidate); err == nil {
				candidate = host
			}
		}
	} else if strings.Contains(candidate, "/") && !strings.Contains(candidate, ".") && !strings.Contains(candidate, ":") {
		// Could be path-like or malformed
	}

	// Strip trailing slashes or path segments if someone entered "example.com/path" without scheme
	if slashIdx := strings.Index(candidate, "/"); slashIdx != -1 {
		// Only strip if not a CIDR (CIDR has IP before the slash)
		prefix := candidate[:slashIdx]
		if net.ParseIP(prefix) == nil {
			candidate = prefix
		}
	}

	// Strip port if formatted as host:port (e.g. 192.168.1.1:8080 or example.com:443)
	if strings.Contains(candidate, ":") && !strings.Contains(candidate, "::") && !strings.Contains(candidate, "/") {
		if host, _, err := net.SplitHostPort(candidate); err == nil {
			candidate = host
		}
	}

	// 1. Check for CIDR (e.g. 192.168.1.0/24 or 2001:db8::/32)
	if strings.Contains(candidate, "/") {
		_, ipNet, err := net.ParseCIDR(candidate)
		if err == nil && ipNet != nil {
			return &models.Target{
				Original: raw,
				Value:    ipNet.String(),
				Type:     models.TargetTypeCIDR,
			}, nil
		}
	}

	// 2. Check for standalone IP (IPv4 vs IPv6)
	if ip := net.ParseIP(candidate); ip != nil {
		if ip.To4() != nil {
			return &models.Target{
				Original: raw,
				Value:    ip.String(),
				Type:     models.TargetTypeIPv4,
			}, nil
		}
		return &models.Target{
			Original: raw,
			Value:    ip.String(),
			Type:     models.TargetTypeIPv6,
		}, nil
	}

	// 3. Check for Domain Name
	normalizedDomain := strings.ToLower(candidate)
	if domainRegex.MatchString(normalizedDomain) {
		return &models.Target{
			Original: raw,
			Value:    normalizedDomain,
			Type:     models.TargetTypeDomain,
		}, nil
	}

	// 4. Default fallback: Organization string
	return &models.Target{
		Original: raw,
		Value:    cleaned,
		Type:     models.TargetTypeOrg,
	}, nil
}
