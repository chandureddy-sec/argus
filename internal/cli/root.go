package cli

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"reconx/internal/archive"
	"reconx/internal/target"
	"reconx/pkg/models"
)

var (
	// Version is injected during build time via -ldflags.
	Version = "0.1.0-dev"

	cfgFile string
	verbose bool
	silent  bool

	// Logger is the application-wide structured logger.
	Logger *slog.Logger
)

// RootCmd represents the base command when called without any subcommands.
var RootCmd = &cobra.Command{
	Use:   "reconx [target]",
	Short: "ReconX is a cross-platform passive reconnaissance and attack surface intelligence CLI",
	Long: `ReconX aggregates, normalizes, deduplicates, and confidence-scores publicly available 
OSINT data across multiple passive providers (DNS, CT logs, RDAP, WHOIS, Threat Feeds) 
without sending intrusive probes to target systems.`,
	Args: cobra.ArbitraryArgs,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		setupLogger()
		loadStoredKeys()
		archive.Install()
	},
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			// No args passed: enter interactive terminal prompt
			StartInteractiveMode()
			return
		}

		// A bare word that isn't a domain or IP is almost always a mistyped
		// subcommand (e.g. `reconx server`); don't run an empty scan on it.
		if t, err := target.Parse(args[0]); err == nil && t.Type == models.TargetTypeOrg {
			fmt.Fprintf(os.Stderr, "Error: %q is not a ReconX command or a domain/IP target.\n", args[0])
			cmd.SuggestionsMinimumDistance = 2
			if s := cmd.SuggestionsFor(args[0]); len(s) > 0 {
				fmt.Fprintf(os.Stderr, "\nDid you mean this?\n\t%s\n", strings.Join(s, "\n\t"))
			}
			fmt.Fprintln(os.Stderr, "\nRun 'reconx --help' for usage.")
			os.Exit(1)
		}

		// Target passed directly (e.g. `reconx tesla.com`)
		RunAutomatedRecon(args[0])
	},
}

func init() {
	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./config.yaml or ./configs/config.yaml)")
	RootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose debug logging")
	RootCmd.PersistentFlags().BoolVarP(&silent, "silent", "q", false, "silent mode: output only results, suppress logs")

	RootCmd.Version = Version
	RootCmd.SetVersionTemplate("ReconX version {{.Version}}\n")

	// Add child subcommands — Phase 1 (Passive OSINT)
	RootCmd.AddCommand(scanCmd)
	RootCmd.AddCommand(subdomainsCmd)
	RootCmd.AddCommand(dnsCmd)
	RootCmd.AddCommand(certificatesCmd)
	RootCmd.AddCommand(ipCmd)
	RootCmd.AddCommand(historyCmd)
	RootCmd.AddCommand(versionCmd)

	// Phase 2 — Active Recon & Web Mapping (requires authorized target)
	RootCmd.AddCommand(probeCmd)
	RootCmd.AddCommand(portscanCmd)
	RootCmd.AddCommand(nmapCmd)
	RootCmd.AddCommand(webmapCmd)

	// Web dashboard
	RootCmd.AddCommand(serveCmd)

	// Configuration & continuous monitoring
	RootCmd.AddCommand(keysCmd)
	RootCmd.AddCommand(monitorCmd)
}

func setupLogger() {
	var level slog.Level
	if silent {
		// Suppress logs by setting high threshold
		level = slog.LevelError + 10
	} else if verbose {
		level = slog.LevelDebug
	} else {
		// Default: keep the formatted report clean. Diagnostic INFO/WARN lines
		// (e.g. per-provider failures, which are already summarized in the
		// "Providers:" line and the degraded sections) are shown only with -v.
		level = slog.LevelError
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	handler := slog.NewTextHandler(os.Stderr, opts)
	Logger = slog.New(handler)
	slog.SetDefault(Logger)
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
