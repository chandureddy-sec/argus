package headers

import (
	"testing"

	"reconx/pkg/models"
)

func sevCount(findings []models.Finding, title string) (count int, sev string) {
	for _, f := range findings {
		if f.Title == title {
			count++
			sev = f.Severity
		}
	}
	return count, sev
}

func TestAnalyzeCookies_SessionCookieMissingFlags(t *testing.T) {
	cookies := []models.CookieInfo{
		{Name: "PHPSESSID", Secure: false, HTTPOnly: false, SameSite: ""},
	}
	findings := AnalyzeCookies(cookies)

	// Expect three findings: Secure, HttpOnly, SameSite.
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings for a bare session cookie, got %d: %+v", len(findings), findings)
	}
	if n, sev := sevCount(findings, "Cookie missing Secure flag"); n != 1 || sev != models.SeverityMedium {
		t.Errorf("session cookie missing Secure should be MEDIUM (got n=%d sev=%s)", n, sev)
	}
	if n, sev := sevCount(findings, "Cookie missing HttpOnly flag"); n != 1 || sev != models.SeverityMedium {
		t.Errorf("session cookie missing HttpOnly should be MEDIUM (got n=%d sev=%s)", n, sev)
	}
}

func TestAnalyzeCookies_HardenedCookieIsClean(t *testing.T) {
	cookies := []models.CookieInfo{
		{Name: "sessionid", Secure: true, HTTPOnly: true, SameSite: "Strict"},
	}
	if findings := AnalyzeCookies(cookies); len(findings) != 0 {
		t.Errorf("a fully hardened cookie should yield no findings, got %d: %+v", len(findings), findings)
	}
}

func TestAnalyzeCookies_NonSessionIsLowerSeverity(t *testing.T) {
	cookies := []models.CookieInfo{
		{Name: "theme_pref", Secure: false, HTTPOnly: true, SameSite: "Lax"},
	}
	findings := AnalyzeCookies(cookies)
	if n, sev := sevCount(findings, "Cookie missing Secure flag"); n != 1 || sev != models.SeverityLow {
		t.Errorf("non-session cookie missing Secure should be LOW (got n=%d sev=%s)", n, sev)
	}
}

func TestAnalyzeCookies_SameSiteNoneWithoutSecure(t *testing.T) {
	cookies := []models.CookieInfo{
		{Name: "tracking", Secure: false, HTTPOnly: true, SameSite: "None"},
	}
	findings := AnalyzeCookies(cookies)
	if n, sev := sevCount(findings, "Cookie SameSite=None without Secure"); n != 1 || sev != models.SeverityMedium {
		t.Errorf("SameSite=None without Secure should be MEDIUM (got n=%d sev=%s)", n, sev)
	}
}
