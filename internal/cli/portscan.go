package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"reconx/internal/modules/portscan"
	"reconx/internal/target"
	"reconx/internal/ui"
)

var (
	portscanTargetFlag  string
	portscanTimeoutFlag int
	portscanFullFlag    bool
)

var portscanCmd = &cobra.Command{
	Use:   "portscan",
	Short: "TCP port scan with service detection and banner grabbing",
	Long: `PortScan probes TCP ports on the target host using connect-scan.
By default it scans the top 23 common TCP ports. Use --full to scan all 65535.
For each open port it attempts a brief banner grab to identify the running service.

Requires explicit authorization to use against any target.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		raw := portscanTargetFlag
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

		if err := ensureAuthorized(host); err != nil {
			return err
		}

		timeoutDur := time.Duration(portscanTimeoutFlag) * time.Millisecond
		if timeoutDur <= 0 {
			timeoutDur = 2 * time.Second
		}

		// A full scan takes a long time, use a much larger context timeout
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
		defer cancel()

		var targetPorts []int
		if portscanFullFlag {
			for i := 1; i <= 65535; i++ {
				targetPorts = append(targetPorts, i)
			}
		} else {
			targetPorts = portscan.CommonPorts
		}

		if !silent {
			fmt.Printf("\n")
			ui.PrintBanner(Version)
			ui.PrintSectionHeader("PORTSCAN", host)
			
			scanTypeStr := fmt.Sprintf("top %d common TCP ports", len(targetPorts))
			if portscanFullFlag {
				scanTypeStr = "all 65,535 TCP ports"
			}
			
			fmt.Printf("\n[*] Scanning %s (timeout: %dms per port)...\n",
				scanTypeStr, portscanTimeoutFlag)
			if portscanFullFlag {
				fmt.Printf("[!] Note: Full connect-scan without raw sockets may take several minutes.\n\n")
			} else {
				fmt.Printf("\n")
			}
		}

		results, err := portscan.ScanPorts(ctx, host, targetPorts, timeoutDur)
		if err != nil {
			return fmt.Errorf("port scan failed: %w", err)
		}

		// Filter to open ports
		var openPorts []struct {
			Port    int
			Service string
			Banner  string
		}
		for _, r := range results {
			if r.State == "open" {
				openPorts = append(openPorts, struct {
					Port    int
					Service string
					Banner  string
				}{r.Port, r.Service, r.Banner})
			}
		}

		if silent {
			for _, r := range results {
				if r.State == "open" {
					fmt.Printf("%d\ttcp\t%s\t%s\n", r.Port, r.Service, r.Banner)
				}
			}
			return nil
		}

		if len(openPorts) == 0 {
			fmt.Printf("[!] No open ports found on %s\n\n", host)
			return nil
		}

		fmt.Printf("[+] %d open port(s) found on %s:\n\n", len(openPorts), host)
		headers := []string{"Port", "Protocol", "Service", "Banner"}
		rows := make([][]string, 0, len(openPorts))
		for _, p := range openPorts {
			banner := p.Banner
			if len(banner) > 60 {
				banner = banner[:57] + "..."
			}
			banner = strings.ReplaceAll(banner, "\r", "")
			banner = strings.ReplaceAll(banner, "\n", " ")
			rows = append(rows, []string{
				fmt.Sprintf("%d", p.Port),
				"tcp",
				p.Service,
				map[bool]string{true: banner, false: "-"}[banner != ""],
			})
		}
		ui.PrintTable(headers, rows)
		fmt.Printf("\n[+] Port scan complete for %s\n\n", host)
		return nil
	},
}

func init() {
	portscanCmd.Flags().StringVarP(&portscanTargetFlag, "target", "t", "", "target host to scan")
	portscanCmd.Flags().IntVar(&portscanTimeoutFlag, "timeout", 2000, "per-port connect timeout in milliseconds")
	portscanCmd.Flags().BoolVar(&portscanFullFlag, "full", false, "scan all 65535 ports instead of top common ports")
	addActiveAuthFlags(portscanCmd.Flags())
}
