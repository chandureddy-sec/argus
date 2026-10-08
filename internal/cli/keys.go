package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"reconx/internal/keystore"
	"reconx/internal/ui"
)

var keysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Manage optional API keys for passive sources (GitHub, urlscan.io, Cert Spotter)",
	Long: `Keys are stored in your user config directory with owner-only permissions and
loaded automatically on every run. An environment variable that is already set
(e.g. RECONX_GITHUB_TOKEN) always takes precedence over the stored key.

Supported keys:
  github       RECONX_GITHUB_TOKEN          required for GitHub code search
  urlscan      RECONX_URLSCAN_API_KEY       richer urlscan.io results, higher quota
  certspotter  RECONX_CERTSPOTTER_API_KEY   higher Cert Spotter quota`,
	RunE: func(cmd *cobra.Command, args []string) error { return listKeys() },
}

var keysListCmd = &cobra.Command{
	Use:   "list",
	Short: "Show which keys are configured (values are masked)",
	RunE:  func(cmd *cobra.Command, args []string) error { return listKeys() },
}

var keysSetCmd = &cobra.Command{
	Use:   "set <name> [value]",
	Short: "Store a key; omit the value to type it hidden (keeps it out of shell history)",
	Args:  cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		k, ok := keystore.Lookup(args[0])
		if !ok {
			return fmt.Errorf("unknown key %q (supported: %s)", args[0], strings.Join(keystore.Names(), ", "))
		}
		value := ""
		if len(args) == 2 {
			value = args[1]
		} else {
			v, err := readSecret(fmt.Sprintf("Paste your %s key (input hidden): ", k.Service))
			if err != nil {
				return err
			}
			value = v
		}
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("no key entered; use `reconx keys unset %s` to remove a key", k.Name)
		}
		st := keystore.Open("")
		if err := st.SetAndApply(k.Name, value); err != nil {
			return err
		}
		fmt.Printf("[+] Saved %s key (%s) to %s\n", k.Name, keystore.Mask(value), st.Path())
		if env := os.Getenv(k.Env); env != "" && env != strings.TrimSpace(value) {
			fmt.Printf("[!] %s is set in your environment and takes precedence over the stored key.\n", k.Env)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		r := keystore.Verify(ctx, k.Name, strings.TrimSpace(value))
		mark := "[+]"
		if !r.OK {
			mark = "[!]"
		}
		fmt.Printf("%s Check with %s: %s\n", mark, k.Service, r.Detail)
		return nil
	},
}

var keysUnsetCmd = &cobra.Command{
	Use:     "unset <name>",
	Aliases: []string{"remove", "rm"},
	Short:   "Remove a stored key",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		k, ok := keystore.Lookup(args[0])
		if !ok {
			return fmt.Errorf("unknown key %q (supported: %s)", args[0], strings.Join(keystore.Names(), ", "))
		}
		if err := keystore.Open("").SetAndApply(k.Name, ""); err != nil {
			return err
		}
		fmt.Printf("[+] Removed stored %s key.\n", k.Name)
		if os.Getenv(k.Env) != "" {
			fmt.Printf("[!] %s is still set in your environment, so the source keeps using it.\n", k.Env)
		}
		return nil
	},
}

var keysTestCmd = &cobra.Command{
	Use:   "test [name]",
	Short: "Check configured keys against their services (no scan target is contacted)",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		names := keystore.Names()
		if len(args) == 1 {
			k, ok := keystore.Lookup(args[0])
			if !ok {
				return fmt.Errorf("unknown key %q", args[0])
			}
			names = []string{k.Name}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		rows := [][]string{}
		for _, n := range names {
			k, _ := keystore.Lookup(n)
			r := keystore.Verify(ctx, k.Name, strings.TrimSpace(os.Getenv(k.Env)))
			status := "OK"
			if !r.OK {
				status = "--"
				if r.Detail != "not set" {
					status = "FAIL"
				}
			}
			rows = append(rows, []string{k.Name, status, r.Detail})
		}
		ui.PrintTable([]string{"Key", "Status", "Detail"}, rows)
		return nil
	},
}

func listKeys() error {
	st := keystore.Open("")
	statuses, err := st.Statuses()
	if err != nil {
		return err
	}
	rows := make([][]string, 0, len(statuses))
	for _, s := range statuses {
		src := map[string]string{"env": "environment", "file": "stored", "unset": "not set"}[s.Source]
		if s.Shadow {
			src += " (overrides stored)"
		}
		rows = append(rows, []string{s.Name, s.Env, src, s.Hint, s.Effect})
	}
	ui.PrintTable([]string{"Key", "Variable", "Source", "Value", "Effect"}, rows)
	fmt.Printf("\nKey file: %s\nSet one with: reconx keys set <name>   ·   check them with: reconx keys test\n", st.Path())
	return nil
}

// readSecret reads a line from the terminal without echo, falling back to a
// plain read when stdin is not a terminal (e.g. piped input).
func readSecret(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Print(prompt)
		b, err := term.ReadPassword(fd)
		fmt.Println()
		return strings.TrimSpace(string(b)), err
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("no key on stdin")
	}
	return strings.TrimSpace(line), nil
}

// loadStoredKeys exports stored API keys into the environment for this
// process. Failures are only logged: a broken key file must never stop a scan.
func loadStoredKeys() {
	if _, err := keystore.Open("").Apply(); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Could not load stored API keys: %v\n", err)
	}
}

func init() {
	keysCmd.AddCommand(keysListCmd, keysSetCmd, keysUnsetCmd, keysTestCmd)
	for _, c := range append(keysCmd.Commands(), keysCmd) {
		c.SilenceUsage = true
	}
}
