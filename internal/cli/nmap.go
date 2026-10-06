package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	nmapmod "reconx/internal/modules/nmap"
	"reconx/internal/target"
	"reconx/internal/ui"
	"reconx/pkg/models"
)

var (
	nmapTargetFlag  string
	nmapProfileFlag string
	nmapPortsFlag   string
	nmapArgsFlag    string
	nmapTimeoutMin  int
)

var nmapCmd = &cobra.Command{
	Use:   "nmap [target]",
	Short: "Run an nmap scan (service/version, scripts, OS detection) against an authorized target",
	Long: `Nmap drives the installed nmap binary and parses its results into ReconX.
It exposes nmap's full power through profiles and a raw-argument passthrough.

Profiles:
  quick       -sV -sC  — service/version detection + default NSE scripts (default)
  aggressive  -A       — version, scripts, OS detection and traceroute
  full        -sV -p-  — service detection across all 65535 ports
  custom      use --args to pass nmap flags directly (e.g. --args "-sU -O --script vuln")

All profiles add -Pn (treat the host as up) and -T4. SYN scans, OS detection and
UDP scanning need Administrator/root; without it nmap falls back automatically and
ReconX reports which mode actually ran.

This sends traffic directly to the target and requires explicit authorization.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		raw := nmapTargetFlag
		if raw == "" && len(args) > 0 {
			raw = args[0]
		}
		if raw == "" {
			return fmt.Errorf("target is required: use --target <host> or pass as argument")
		}
		parsed, err := target.Parse(raw)
		if err != nil {
			return fmt.Errorf("invalid target: %w", err)
		}
		host := parsed.Value

		if !nmapmod.Available() {
			return fmt.Errorf("nmap is not installed or not on PATH.\n" +
				"   Install it and re-run — on Windows: winget install Insecure.Nmap")
		}
		if err := ensureAuthorized(host); err != nil {
			return err
		}

		opts := nmapmod.Options{
			Profile: strings.ToLower(nmapProfileFlag),
			Ports:   nmapPortsFlag,
			Timeout: time.Duration(nmapTimeoutMin) * time.Minute,
		}
		if strings.TrimSpace(nmapArgsFlag) != "" {
			opts.Profile = nmapmod.ProfileCustom
			opts.Args = strings.Fields(nmapArgsFlag)
			if err := nmapmod.ValidateArgs(opts.Args); err != nil {
				return err
			}
		}

		if !silent {
			fmt.Printf("\n")
			ui.PrintBanner(Version)
			ui.PrintSectionHeader("NMAP", host)
			fmt.Printf("\n[*] Profile: %s · this may take a while; nmap is scanning %s...\n\n",
				firstNonEmptyStr(opts.Profile, "quick"), host)
		}

		ctx := context.Background()
		res, err := nmapmod.Run(ctx, host, opts)
		if err != nil {
			return fmt.Errorf("nmap scan failed: %w", err)
		}
		if !res.Available {
			return fmt.Errorf("%s", res.Unavailable)
		}
		printNmapResult(res, host)
		return nil
	},
}

func init() {
	nmapCmd.Flags().StringVarP(&nmapTargetFlag, "target", "t", "", "target host to scan")
	nmapCmd.Flags().StringVar(&nmapProfileFlag, "profile", "quick", "scan profile: quick | aggressive | full")
	nmapCmd.Flags().StringVar(&nmapPortsFlag, "ports", "", "port spec passed to nmap -p (e.g. \"1-1024,8080\")")
	nmapCmd.Flags().StringVar(&nmapArgsFlag, "args", "", "raw nmap flags (overrides --profile), e.g. \"-sU -O --script vuln\"")
	nmapCmd.Flags().IntVar(&nmapTimeoutMin, "timeout", 0, "overall timeout in minutes (0 = profile default)")
	addActiveAuthFlags(nmapCmd.Flags())
}

// printNmapResult renders a scan result to the terminal.
func printNmapResult(res *models.NmapResult, host string) {
	if silent {
		for _, p := range res.Ports {
			if p.State == "open" {
				fmt.Printf("%d\t%s\t%s\t%s\n", p.Port, p.Protocol, p.Service, p.VersionString())
			}
		}
		return
	}

	privNote := "unprivileged (connect scan; run as Administrator for SYN/OS detection)"
	if res.Privileged {
		privNote = "privileged (raw packets)"
	}
	fmt.Printf("[+] nmap %s · %s scan · %s · %.1fs\n", res.Version, orDash(res.ScanType), privNote, res.ElapsedSec)
	fmt.Printf("    %s\n\n", res.Command)

	if res.HostState != "up" {
		fmt.Printf("[!] Host reported %s by nmap. (Add --args \"-Pn\" is already applied; the host may be blocking or offline.)\n\n", orDash(res.HostState))
	}

	open := 0
	for _, p := range res.Ports {
		if p.State == "open" {
			open++
		}
	}
	if open == 0 {
		fmt.Printf("[!] No open ports reported on %s.\n", host)
	} else {
		fmt.Printf("[+] %d open port(s) on %s:\n\n", open, host)
		headers := []string{"Port", "Proto", "State", "Service", "Version / Product"}
		rows := make([][]string, 0, len(res.Ports))
		for _, p := range res.Ports {
			if p.State != "open" {
				continue
			}
			rows = append(rows, []string{
				fmt.Sprintf("%d", p.Port), p.Protocol, p.State, orDash(p.Service), orDash(p.VersionString()),
			})
		}
		ui.PrintTable(headers, rows)
	}

	if len(res.OSMatches) > 0 {
		fmt.Printf("\n[+] OS detection (best guesses):\n")
		for i, m := range res.OSMatches {
			if i >= 3 {
				break
			}
			fmt.Printf("    %d%%  %s\n", m.Accuracy, m.Name)
		}
	}

	// NSE script output, trimmed so the terminal stays readable.
	printed := false
	for _, p := range res.Ports {
		for _, s := range p.Scripts {
			if !printed {
				fmt.Printf("\n[+] Script results:\n")
				printed = true
			}
			fmt.Printf("    %d/%s %s:\n%s\n", p.Port, p.Protocol, s.ID, indent(trimScript(s.Output), "      "))
		}
	}
	for _, s := range res.HostScripts {
		if !printed {
			fmt.Printf("\n[+] Script results:\n")
			printed = true
		}
		fmt.Printf("    host %s:\n%s\n", s.ID, indent(trimScript(s.Output), "      "))
	}

	if len(res.Warnings) > 0 {
		fmt.Printf("\n[*] nmap notices:\n")
		for _, w := range res.Warnings {
			fmt.Printf("    %s\n", w)
		}
	}
	fmt.Printf("\n[+] nmap scan complete for %s\n\n", host)
}

func trimScript(s string) string {
	const max = 1200
	if len(s) > max {
		return s[:max] + "\n… (truncated; full output in the JSON report)"
	}
	return s
}

func indent(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func firstNonEmptyStr(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
