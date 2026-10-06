package headers

import (
	"strings"

	"reconx/pkg/models"
)

// sessionCookieHints are substrings that commonly identify a session or auth
// cookie, whose missing security flags are a higher-severity finding than for
// an ordinary cookie.
var sessionCookieHints = []string{
	"session", "sessid", "sid", "auth", "token", "jwt", "login",
	"phpsessid", "jsessionid", "asp.net_sessionid", "connect.sid",
}

// isSessionCookie reports whether a cookie name looks session/auth related.
func isSessionCookie(name string) bool {
	lower := strings.ToLower(name)
	for _, hint := range sessionCookieHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

// AnalyzeCookies inspects cookies captured from the target's responses and
// flags missing Secure / HttpOnly / SameSite protections (blueprint Phase 3 —
// Cookie analysis). Session/auth cookies are rated more severely. This is
// static analysis of already-received Set-Cookie data; it sends no new traffic.
func AnalyzeCookies(cookies []models.CookieInfo) []models.Finding {
	var findings []models.Finding

	for _, c := range cookies {
		session := isSessionCookie(c.Name)

		// Secure: without it, the cookie can leak over plaintext HTTP.
		if !c.Secure {
			sev := models.SeverityLow
			if session {
				sev = models.SeverityMedium
			}
			findings = append(findings, models.Finding{
				Category:              "Cookie Security",
				Severity:              sev,
				Title:                 "Cookie missing Secure flag",
				Description:           "Cookie \"" + c.Name + "\" is not marked Secure and may be transmitted over unencrypted HTTP.",
				Evidence:              c.Name,
				RequiresTargetContact: true,
			})
		}

		// HttpOnly: without it, the cookie is reachable from JavaScript (XSS theft).
		if !c.HTTPOnly {
			sev := models.SeverityLow
			if session {
				sev = models.SeverityMedium
			}
			findings = append(findings, models.Finding{
				Category:              "Cookie Security",
				Severity:              sev,
				Title:                 "Cookie missing HttpOnly flag",
				Description:           "Cookie \"" + c.Name + "\" is not marked HttpOnly and is accessible to client-side scripts.",
				Evidence:              c.Name,
				RequiresTargetContact: true,
			})
		}

		// SameSite: absent weakens CSRF defenses; "None" without Secure is worse.
		switch strings.ToLower(strings.TrimSpace(c.SameSite)) {
		case "":
			findings = append(findings, models.Finding{
				Category:              "Cookie Security",
				Severity:              models.SeverityLow,
				Title:                 "Cookie missing SameSite attribute",
				Description:           "Cookie \"" + c.Name + "\" has no SameSite attribute, weakening CSRF protection.",
				Evidence:              c.Name,
				RequiresTargetContact: true,
			})
		case "none":
			if !c.Secure {
				findings = append(findings, models.Finding{
					Category:              "Cookie Security",
					Severity:              models.SeverityMedium,
					Title:                 "Cookie SameSite=None without Secure",
					Description:           "Cookie \"" + c.Name + "\" uses SameSite=None but is not Secure; browsers reject this and it exposes the cookie cross-site.",
					Evidence:              c.Name,
					RequiresTargetContact: true,
				})
			}
		}
	}

	return findings
}
