package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ValidateWebhook accepts empty (no webhook) or an http(s) URL.
func ValidateWebhook(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("webhook must be an http(s) URL")
	}
	return nil
}

// WebhookKind identifies the payload format a webhook URL expects.
func WebhookKind(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "generic"
	}
	host := strings.ToLower(u.Hostname())
	switch {
	case host == "hooks.slack.com":
		return "slack"
	case (host == "discord.com" || host == "discordapp.com" || strings.HasSuffix(host, ".discord.com")) && strings.HasPrefix(u.Path, "/api/webhooks/"):
		return "discord"
	case strings.HasSuffix(host, ".webhook.office.com") || strings.HasSuffix(host, ".logic.azure.com"):
		return "teams"
	default:
		return "generic"
	}
}

// MaskWebhook hides the secret part of a webhook URL for display.
func MaskWebhook(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host + "/…"
}

// Text renders an alert as plain text for chat webhooks and the terminal.
func (a Alert) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "[ReconX %s] %s", strings.ToUpper(a.Severity), a.Title)
	for _, it := range a.Items {
		b.WriteString("\n• " + it)
	}
	if a.More > 0 {
		fmt.Fprintf(&b, "\n…and %d more", a.More)
	}
	if a.ScanFile != "" {
		b.WriteString("\nScan: reports/" + a.ScanFile)
	}
	return b.String()
}

// Notifier delivers alerts to a monitor's webhook.
type Notifier struct {
	Client *http.Client
}

// Send posts alerts at or above the monitor's minimum severity, one request
// per alert, and records the outcome on each alert's Delivered field.
func (n *Notifier) Send(ctx context.Context, m *Monitor, alerts []Alert) {
	for i := range alerts {
		a := &alerts[i]
		switch {
		case m.Webhook == "":
			a.Delivered = ""
		case !AtLeast(a.Severity, firstNonEmpty(m.MinSeverity, SevLow)):
			a.Delivered = "skipped (below " + m.MinSeverity + ")"
		default:
			if err := n.post(ctx, m.Webhook, *a); err != nil {
				a.Delivered = "failed: " + err.Error()
			} else {
				a.Delivered = "sent"
			}
		}
	}
}

// Test sends a sample alert to the monitor's webhook.
func (n *Notifier) Test(ctx context.Context, m *Monitor) error {
	if m.Webhook == "" {
		return fmt.Errorf("monitor %s has no webhook", m.Target)
	}
	return n.post(ctx, m.Webhook, Alert{
		ID: "test", MonitorID: m.ID, Target: m.Target, Time: time.Now().UTC(), Rule: "test", Severity: SevInfo,
		Title: "Test alert for " + m.Target + " — webhook is working",
	})
}

func (n *Notifier) post(ctx context.Context, hook string, a Alert) error {
	var payload interface{}
	switch WebhookKind(hook) {
	case "slack", "teams":
		payload = map[string]string{"text": a.Text()}
	case "discord":
		text := a.Text()
		if len(text) > 1900 { // Discord rejects content over 2000 characters
			text = text[:1900] + "…"
		}
		payload = map[string]string{"content": text}
	default:
		payload = map[string]interface{}{"text": a.Text(), "alert": a}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	client := n.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, hook, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ReconX/1.0 monitor")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}
