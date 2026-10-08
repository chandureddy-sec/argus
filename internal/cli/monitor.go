package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"reconx/internal/history"
	"reconx/internal/monitor"
	"reconx/internal/target"
	"reconx/internal/ui"
	"reconx/pkg/models"
)

var (
	monEvery       string
	monWebhook     string
	monMinSeverity string
	monRules       string
	monArchiveRaw  bool
	monAll         bool
	monAlertsLimit int
	monTick        time.Duration
)

var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Schedule passive re-scans of targets and alert on attack-surface changes",
	Long: `Monitors re-run a Passive scan of a domain on a schedule, save it to reports/
like any scan, compare it with the previous saved scan, and raise alerts for new
subdomains, DNS changes, new exposure, expiring certificates and more. Alerts are
logged to reports/monitor/alerts.jsonl, shown in the dashboard, and optionally
POSTed to a Slack, Discord, Teams or generic JSON webhook.

Monitors never send traffic to the target: they use only the public sources a
manual Passive scan uses.

Schedules run while 'reconx serve' or 'reconx monitor daemon' is running. To run
without a long-lived process, call 'reconx monitor run' from Task Scheduler or cron.`,
	RunE: func(cmd *cobra.Command, args []string) error { return listMonitors() },
}

var monitorAddCmd = &cobra.Command{
	Use:   "add <domain>",
	Short: "Start monitoring a domain (the first scan runs at the next scheduler check)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		t, err := target.Parse(args[0])
		if err != nil || t.Type != models.TargetTypeDomain {
			return fmt.Errorf("%q is not a domain", args[0])
		}
		every, err := monitor.ParseDuration(monEvery)
		if err != nil {
			return err
		}
		var rules []string
		if monRules != "" {
			for _, r := range strings.Split(monRules, ",") {
				rules = append(rules, strings.TrimSpace(r))
			}
		}
		m, err := monitor.OpenStore("").Add(monitor.Monitor{
			Target: t.Value, Interval: monitor.Duration(every), Webhook: strings.TrimSpace(monWebhook),
			MinSeverity: monMinSeverity, Rules: rules, ArchiveRaw: monArchiveRaw,
		})
		if err != nil {
			return err
		}
		fmt.Printf("[+] Monitoring %s every %s (id %s)\n", m.Target, m.Interval, m.ID)
		if m.Webhook != "" {
			fmt.Printf("[*] Alerts ≥ %s go to a %s webhook (%s). Check it with: reconx monitor test-webhook %s\n",
				m.MinSeverity, monitor.WebhookKind(m.Webhook), monitor.MaskWebhook(m.Webhook), m.ID)
		}
		fmt.Println("[*] Run it now with `reconx monitor run " + m.ID + "`, or keep `reconx serve` / `reconx monitor daemon` running.")
		return nil
	},
}

var monitorListCmd = &cobra.Command{
	Use:   "list",
	Short: "List monitors and their last run",
	RunE:  func(cmd *cobra.Command, args []string) error { return listMonitors() },
}

var monitorRemoveCmd = &cobra.Command{
	Use:     "remove <id|domain>",
	Aliases: []string{"rm", "delete"},
	Short:   "Stop monitoring a target (its saved scans and alerts are kept)",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		st := monitor.OpenStore("")
		m, err := st.Find(args[0])
		if err != nil {
			return err
		}
		if err := st.Remove(m.ID); err != nil {
			return err
		}
		fmt.Printf("[+] Stopped monitoring %s.\n", m.Target)
		return nil
	},
}

func setEnabled(enabled bool) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		st := monitor.OpenStore("")
		m, err := st.Find(args[0])
		if err != nil {
			return err
		}
		if _, err := st.Update(m.ID, func(x *monitor.Monitor) error {
			x.Enabled = enabled
			if enabled && x.NextRun.Before(time.Now()) {
				x.NextRun = time.Now().UTC()
			}
			return nil
		}); err != nil {
			return err
		}
		state := map[bool]string{true: "resumed", false: "paused"}[enabled]
		fmt.Printf("[+] Monitor for %s %s.\n", m.Target, state)
		return nil
	}
}

var monitorPauseCmd = &cobra.Command{Use: "pause <id|domain>", Short: "Pause a monitor", Args: cobra.ExactArgs(1), RunE: setEnabled(false)}
var monitorResumeCmd = &cobra.Command{Use: "resume <id|domain>", Short: "Resume a paused monitor", Args: cobra.ExactArgs(1), RunE: setEnabled(true)}

var monitorRunCmd = &cobra.Command{
	Use:   "run [id|domain]",
	Short: "Run due monitors once and exit (or one monitor now); suits Task Scheduler / cron",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		r := newMonitorRunner(func(s string) { fmt.Println("[*] " + s) })
		r.OnAlerts = printAlerts
		r.RecoverInterrupted()
		switch {
		case len(args) == 1:
			m, err := r.Store.Find(args[0])
			if err != nil {
				return err
			}
			_, err = r.RunOne(ctx, m.ID)
			return err
		case monAll:
			ms, err := r.Store.List()
			if err != nil {
				return err
			}
			for _, m := range ms {
				if m.Enabled {
					_, _ = r.RunOne(ctx, m.ID)
				}
			}
		default:
			if n := r.RunDue(ctx, time.Now().UTC()); n == 0 {
				fmt.Println("[*] No monitors are due. Use --all to run every enabled monitor now.")
			}
		}
		return nil
	},
}

var monitorDaemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Run the monitor scheduler in the foreground until Ctrl+C",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		r := newMonitorRunner(func(s string) { fmt.Printf("%s  %s\n", time.Now().Format("2006-01-02 15:04:05"), s) })
		r.OnAlerts = printAlerts
		fmt.Printf("ReconX monitor scheduler — checking every %s. Press Ctrl+C to stop.\n", monTick)
		r.Loop(ctx, monTick)
		return nil
	},
}

var monitorAlertsCmd = &cobra.Command{
	Use:   "alerts [domain]",
	Short: "Show recent alerts, newest first",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		tgt := ""
		if len(args) == 1 {
			tgt = args[0]
		}
		alerts, err := monitor.OpenStore("").Alerts(tgt, monAlertsLimit)
		if err != nil {
			return err
		}
		if len(alerts) == 0 {
			fmt.Println("No alerts yet.")
			return nil
		}
		for i := len(alerts) - 1; i >= 0; i-- { // oldest first reads naturally in a terminal
			a := alerts[i]
			fmt.Printf("\n%s  %s\n", a.Time.Local().Format("2006-01-02 15:04"), a.Text())
			if a.Delivered != "" {
				fmt.Printf("  webhook: %s\n", a.Delivered)
			}
		}
		return nil
	},
}

var monitorTestWebhookCmd = &cobra.Command{
	Use:   "test-webhook <id|domain>",
	Short: "Send a test alert to a monitor's webhook",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		m, err := monitor.OpenStore("").Find(args[0])
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := (&monitor.Notifier{}).Test(ctx, m); err != nil {
			return fmt.Errorf("webhook test failed: %w", err)
		}
		fmt.Printf("[+] Test alert delivered to the %s webhook.\n", monitor.WebhookKind(m.Webhook))
		return nil
	},
}

var monitorRulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "List the alert rules (use with monitor add --rules)",
	Run: func(cmd *cobra.Command, args []string) {
		rows := [][]string{}
		for _, r := range monitor.Rules {
			rows = append(rows, []string{r.ID, r.Description})
		}
		ui.PrintTable([]string{"Rule", "Alerts when"}, rows)
	},
}

func listMonitors() error {
	ms, err := monitor.OpenStore("").List()
	if err != nil {
		return err
	}
	if len(ms) == 0 {
		fmt.Println("No monitors. Add one with: reconx monitor add example.com --every 1d")
		return nil
	}
	rows := [][]string{}
	for _, m := range ms {
		state := "active"
		if !m.Enabled {
			state = "paused"
		}
		last := "never"
		if !m.LastRun.IsZero() {
			last = m.LastRun.Local().Format("2006-01-02 15:04") + " · " + firstNonEmptyStr(m.LastStatus, "?")
			if m.LastStatus == "ok" {
				last += fmt.Sprintf(" · %d alert(s)", m.LastAlerts)
			}
		}
		next := m.NextRun.Local().Format("2006-01-02 15:04")
		if !m.Enabled {
			next = "-"
		}
		hook := "-"
		if m.Webhook != "" {
			hook = monitor.WebhookKind(m.Webhook) + " ≥" + m.MinSeverity
		}
		rows = append(rows, []string{m.ID, m.Target, m.Interval.String(), state, last, next, hook})
		if m.LastError != "" {
			rows = append(rows, []string{"", "  └ " + m.LastError, "", "", "", "", ""})
		}
	}
	ui.PrintTable([]string{"ID", "Target", "Every", "State", "Last run", "Next run", "Webhook"}, rows)
	return nil
}

func printAlerts(alerts []monitor.Alert) {
	for _, a := range alerts {
		fmt.Println(a.Text())
		if a.Delivered != "" {
			fmt.Println("  webhook: " + a.Delivered)
		}
	}
}

// newMonitorRunner wires the monitor runner to ReconX's passive pipeline.
// Each run is persisted to reports/ so history and diffs include it.
func newMonitorRunner(log func(string)) *monitor.Runner {
	return &monitor.Runner{
		Store:    monitor.OpenStore(""),
		Notifier: &monitor.Notifier{},
		Log:      log,
		Scan: func(ctx context.Context, m *monitor.Monitor) (*models.ScanReport, string, error) {
			res, err := RunScanPipeline(ctx, ScanOptions{Target: m.Target, Mode: "passive", Persist: true, ArchiveRaw: m.ArchiveRaw}, nil)
			if err != nil {
				return nil, "", err
			}
			file := ""
			for _, f := range res.Files {
				if strings.HasSuffix(f, ".json") {
					file = filepath.Base(f)
				}
			}
			if file == "" {
				return res.Report, "", fmt.Errorf("scan finished but its report could not be saved")
			}
			return res.Report, file, nil
		},
		Previous: func(t string) (*models.ScanReport, string) {
			scans := history.LoadTarget("reports", t)
			if len(scans) == 0 {
				return nil, ""
			}
			last := scans[len(scans)-1]
			return last.Report, last.File
		},
	}
}

func init() {
	monitorAddCmd.Flags().StringVar(&monEvery, "every", "1d", "scan interval, e.g. 6h, 1d, 1w (minimum 1h)")
	monitorAddCmd.Flags().StringVar(&monWebhook, "webhook", "", "Slack / Discord / Teams / generic JSON webhook URL for alerts")
	monitorAddCmd.Flags().StringVar(&monMinSeverity, "min-severity", "low", "lowest alert severity sent to the webhook: high | medium | low | info")
	monitorAddCmd.Flags().StringVar(&monRules, "rules", "", "comma-separated alert rules (default all; list them with: reconx monitor rules)")
	monitorAddCmd.Flags().BoolVar(&monArchiveRaw, "archive-raw", false, "archive raw source responses on every run")
	monitorRunCmd.Flags().BoolVar(&monAll, "all", false, "run every enabled monitor now, not only due ones")
	monitorAlertsCmd.Flags().IntVarP(&monAlertsLimit, "limit", "n", 20, "number of alerts to show (0 = all)")
	monitorDaemonCmd.Flags().DurationVar(&monTick, "check-every", time.Minute, "how often to look for due monitors")

	monitorCmd.AddCommand(monitorAddCmd, monitorListCmd, monitorRemoveCmd, monitorPauseCmd, monitorResumeCmd,
		monitorRunCmd, monitorDaemonCmd, monitorAlertsCmd, monitorTestWebhookCmd, monitorRulesCmd)
	// Errors here are input problems ("already monitored", bad interval);
	// the message says what to fix, so skip the usage dump.
	for _, c := range append(monitorCmd.Commands(), monitorCmd) {
		c.SilenceUsage = true
	}
}
