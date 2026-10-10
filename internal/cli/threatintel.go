package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"reconx/internal/threatlens"
	"reconx/internal/ui"
	"reconx/pkg/models"
)

// threatlensFlagEnv is the value --threatlens takes when given without a URL:
// use RECONX_THREATLENS_URL.
const threatlensFlagEnv = "env"

// threatlensConfig turns the --threatlens / --threatlens-tlp flags into a
// validated config. ok is false when the scan should not use ThreatLens.
func threatlensConfig(flagURL, tlp string, budget int) (threatlens.Config, bool, error) {
	if flagURL == "" {
		return threatlens.Config{}, false, nil
	}
	cfg := threatlens.Config{TLP: tlp, Budget: budget}
	if flagURL != threatlensFlagEnv {
		cfg.URL = flagURL
	}
	cfg = cfg.FromEnv()
	if err := cfg.Validate(); err != nil {
		return cfg, false, err
	}
	return cfg, true, nil
}

// gatherThreatIntel sends the scan's hosts and IPs to ThreatLens and stores
// the verdicts on the report. ThreatLens problems never fail the scan: they
// are recorded on report.ThreatIntel instead.
func gatherThreatIntel(ctx context.Context, report *models.ScanReport, cfg threatlens.Config) *models.ThreatIntel {
	values := threatlens.Values(report)
	if len(values) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	report.ThreatIntel = threatlens.New(cfg).Enrich(ctx, values)
	return report.ThreatIntel
}

// importAssets sends the scan to ThreatLens as the organization's own assets.
func importAssets(report *models.ScanReport, cfg threatlens.Config, silent bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := threatlens.New(cfg).ImportAssets(ctx, report)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] ThreatLens asset import failed: %v\n", err)
		return
	}
	if silent {
		return
	}
	if res.Duplicate {
		fmt.Printf("[*] ThreatLens: this scan was already imported (import #%d).\n", res.ImportID)
		return
	}
	fmt.Printf("[+] ThreatLens imported %d hosts, %d IPs and %d products as own assets (%d new, %d updated, %d not imported: private, name-server or CDN addresses).\n",
		res.Hosts, res.IPs, res.Products, res.NewAssets, res.UpdatedAssets, len(res.Rejected))
}

// printThreatIntel shows the flagged assets in the terminal.
func printThreatIntel(ti *models.ThreatIntel) {
	if ti == nil {
		fmt.Println("[*] ThreatLens: nothing to check (no hosts or IPs).")
		return
	}
	if ti.Status == "error" {
		fmt.Fprintf(os.Stderr, "[!] ThreatLens: %s\n", ti.Error)
		return
	}
	c := ti.Counts
	fmt.Printf("[+] ThreatLens (%s, %s): %d checked — %d malicious, %d suspicious, %d benign, %d unknown\n",
		ti.Server, ti.TLP, len(ti.Items), c["malicious"], c["suspicious"], c["benign"], c["unknown"])
	if ti.Error != "" {
		fmt.Fprintf(os.Stderr, "[!] ThreatLens stopped part-way: %s\n", ti.Error)
	}
	flagged := threatlens.Flagged(ti)
	if len(flagged) == 0 {
		fmt.Println("[+] No host or IP is flagged by ThreatLens.")
		return
	}
	rows := make([][]string, 0, len(flagged))
	for _, v := range flagged {
		why := "-"
		if len(v.Evidence) > 0 {
			why = v.Evidence[0].Source + ": " + v.Evidence[0].Text
			if len(why) > 70 {
				why = why[:67] + "..."
			}
		}
		rows = append(rows, []string{v.Defanged, strings.ToUpper(v.Verdict), fmt.Sprintf("%d", v.Score), v.Action, why})
	}
	ui.PrintTable([]string{"Asset", "Verdict", "Score", "Action", "Strongest evidence"}, rows)
}
