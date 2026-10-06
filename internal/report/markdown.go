package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"reconx/pkg/models"
)

// GenerateMarkdown creates a professional Markdown report for pentest engagement notes.
func GenerateMarkdown(report *models.ScanReport, destPath string) error {
	if destPath == "" {
		_ = os.MkdirAll("reports", 0755)
		destPath = filepath.Join("reports", fmt.Sprintf("report_%s_%s.md", report.Target.Value, report.Timestamp.Format("20060102_150405")))
	}
	return os.WriteFile(destPath, []byte(RenderMarkdown(report)), 0644)
}

// RenderMarkdown builds the Markdown report and returns it as a string, for
// in-memory use (e.g. on-demand downloads) without touching disk.
func RenderMarkdown(report *models.ScanReport) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# ReconX Reconnaissance Report: `%s`\n\n", report.Target.Value))
	sb.WriteString(fmt.Sprintf("- **Target:** `%s` (%s)\n", report.Target.Value, report.Target.Type))
	sb.WriteString(fmt.Sprintf("- **Date:** %s\n", report.Timestamp.Format("2006-01-02 15:04:05 UTC")))
	if report.ActiveRecon != nil || report.WebMap != nil {
		sb.WriteString("- **Mode:** Active Recon — includes direct-to-target probes\n\n")
	} else {
		sb.WriteString("- **Mode:** 100% Passive OSINT — Zero intrusive probes\n\n")
	}
	sb.WriteString("---\n\n")

	// ── Executive Summary ──────────────────────────────────────────────────────────
	sb.WriteString("## Executive Summary\n\n")
	sb.WriteString("| Metric | Value |\n")
	sb.WriteString("| :--- | :--- |\n")
	if report.RDAP != nil {
		sb.WriteString(fmt.Sprintf("| Registrar | %s |\n", report.RDAP.Registrar))
		if report.RDAP.Organization != "" {
			sb.WriteString(fmt.Sprintf("| Registrant Org | %s |\n", report.RDAP.Organization))
		}
		if report.RDAP.Country != "" {
			sb.WriteString(fmt.Sprintf("| Country | %s |\n", report.RDAP.Country))
		}
		if !report.RDAP.CreatedDate.IsZero() {
			sb.WriteString(fmt.Sprintf("| Created | %s |\n", report.RDAP.CreatedDate.Format("2006-01-02")))
		}
		if !report.RDAP.ExpiryDate.IsZero() {
			sb.WriteString(fmt.Sprintf("| Expires | %s |\n", report.RDAP.ExpiryDate.Format("2006-01-02")))
		}
		if !report.RDAP.UpdatedDate.IsZero() {
			sb.WriteString(fmt.Sprintf("| Last Updated | %s |\n", report.RDAP.UpdatedDate.Format("2006-01-02")))
		}
		if len(report.RDAP.Nameservers) > 0 {
			sb.WriteString(fmt.Sprintf("| Nameservers | %s |\n", strings.Join(report.RDAP.Nameservers, ", ")))
		}
		if len(report.RDAP.Status) > 0 {
			sb.WriteString(fmt.Sprintf("| Domain Status | %s |\n", strings.Join(report.RDAP.Status, ", ")))
		}
	}
	sb.WriteString(fmt.Sprintf("| Total Discovered Assets | %d |\n", len(report.Assets)))
	if report.Correlation != nil {
		sb.WriteString(fmt.Sprintf("| Resolving Hosts | %d / %d |\n", report.Correlation.LiveAssets, report.Correlation.TotalAssets))
	}
	if report.DNS != nil {
		sb.WriteString(fmt.Sprintf("| DNS Records | %d |\n", len(report.DNS.Records)))
		spf := report.DNS.SecurityRecords.SPF
		if spf == "" {
			spf = "not published"
		}
		dmarc := report.DNS.SecurityRecords.DMARC
		if dmarc == "" {
			dmarc = "not published"
		}
		sb.WriteString(fmt.Sprintf("| SPF Policy | `%s` |\n", spf))
		sb.WriteString(fmt.Sprintf("| DMARC Policy | `%s` |\n", dmarc))
	}
	sb.WriteString("\n---\n\n")

	// ── Passive intelligence (replaces the legacy correlation table) ──────────────
	if report.Intel != nil {
		writeIntelMarkdown(&sb, report)
	} else if report.Correlation != nil && len(report.Correlation.Nodes) > 0 {
		// ── Attack Surface Correlation (reports made before passive intel) ──
		sb.WriteString("## Attack Surface (Correlated Infrastructure)\n\n")
		sb.WriteString("| # | Subdomain | Status | Resolved IP(s) | Cloud / Provider | ASN / Org |\n")
		sb.WriteString("| :--- | :--- | :--- | :--- | :--- | :--- |\n")
		for i, n := range report.Correlation.Nodes {
			status := "no DNS"
			if n.IsAlive {
				status = "**resolves**"
			}
			cloud := n.CloudProvider
			if cloud == "" {
				cloud = "-"
			}
			asn := n.ASN
			if asn == "" {
				asn = n.Organization
			}
			if asn == "" {
				asn = "-"
			}
			sb.WriteString(fmt.Sprintf("| %d | `%s` | %s | %s | %s | %s |\n",
				i+1, n.Hostname, status, n.PrimaryIPString(), cloud, asn,
			))
		}
		sb.WriteString("\n---\n\n")
	} else if len(report.Assets) > 0 {
		// Fallback: show normalized assets when correlation hasn't run
		sb.WriteString("## Discovered Subdomains\n\n")
		sb.WriteString("| # | Subdomain | Sources | Confidence |\n")
		sb.WriteString("| :--- | :--- | :--- | :--- |\n")
		for i, a := range report.Assets {
			sb.WriteString(fmt.Sprintf("| %d | `%s` | %s | %.2f |\n",
				i+1, a.Asset, strings.Join(a.Sources, ", "), a.Confidence,
			))
		}
		sb.WriteString("\n---\n\n")
	}

	// ── DNS Records ────────────────────────────────────────────────────────────────
	if report.DNS != nil && len(report.DNS.Records) > 0 {
		sb.WriteString("## DNS Records\n\n")
		sb.WriteString("| Type | Name | TTL | Value |\n")
		sb.WriteString("| :--- | :--- | :--- | :--- |\n")
		for _, r := range report.DNS.Records {
			sb.WriteString(fmt.Sprintf("| %s | `%s` | %d | `%s` |\n", r.Type, r.Name, r.TTL, r.Value))
		}
		sb.WriteString("\n")

		// Email security (the detailed analysis is in the intel section)
		if report.Intel == nil {
			sb.WriteString("### Email Security Posture\n\n")
			spf := report.DNS.SecurityRecords.SPF
			if spf == "" {
				spf = "not published — receivers can't verify authorized senders"
			}
			dmarc := report.DNS.SecurityRecords.DMARC
			if dmarc == "" {
				dmarc = "not published — no domain-owner policy for failing mail"
			}
			sb.WriteString(fmt.Sprintf("- **SPF:** `%s`\n", spf))
			sb.WriteString(fmt.Sprintf("- **DMARC:** `%s`\n\n", dmarc))
		}
		sb.WriteString("---\n\n")
	}

	// ── Active Recon & Web Mapping ─────────────────────────────────────────────────
	if report.ActiveRecon != nil {
		writeActiveReconMarkdown(&sb, report.ActiveRecon)
	}
	if report.WebMap != nil {
		writeWebMapMarkdown(&sb, report.WebMap)
	}

	// ── Footer ─────────────────────────────────────────────────────────────────────
	sb.WriteString("---\n\n")
	sb.WriteString("*Generated by **ReconX** — For authorized security assessments only.*\n")

	return sb.String()
}
