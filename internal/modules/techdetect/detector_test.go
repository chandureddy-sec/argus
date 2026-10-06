package techdetect

import (
	"testing"

	"reconx/pkg/models"
)

func TestDetect_ServerAndLanguage(t *testing.T) {
	probe := &models.HTTPProbeResult{
		Server:    "Apache/2.4.52",
		PoweredBy: "PHP/8.1.2",
		Headers:   map[string]string{},
	}
	stack := Detect(probe)
	if stack.WebServer != "Apache" {
		t.Errorf("expected WebServer Apache, got %q", stack.WebServer)
	}
	if stack.Language != "PHP" {
		t.Errorf("expected Language PHP, got %q", stack.Language)
	}
}

func TestDetect_CloudflareCDNandWAF(t *testing.T) {
	probe := &models.HTTPProbeResult{
		Headers: map[string]string{"CF-RAY": "7xyz-SJC", "Server": "cloudflare"},
	}
	stack := Detect(probe)
	if stack.CDN != "Cloudflare" {
		t.Errorf("expected CDN Cloudflare, got %q", stack.CDN)
	}
	if stack.WAF != "Cloudflare" {
		t.Errorf("expected WAF Cloudflare, got %q", stack.WAF)
	}
}

func TestDetect_WordPressFromCookie(t *testing.T) {
	probe := &models.HTTPProbeResult{
		Headers: map[string]string{},
		Cookies: []models.CookieInfo{{Name: "wordpress_logged_in_abc"}},
	}
	if stack := Detect(probe); stack.CMS != "WordPress" {
		t.Errorf("expected CMS WordPress, got %q", stack.CMS)
	}
}

func TestDetect_NilProbeIsSafe(t *testing.T) {
	if stack := Detect(nil); stack == nil {
		t.Fatal("Detect(nil) must return a non-nil empty stack")
	}
}
