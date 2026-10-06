package ui

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// Terminal Color Definitions:
// Ghost Green: #D7FFE0 -> rgb(215, 255, 224)
// Bright Neon Cyan/Aqua: #00F5D4 -> rgb(0, 245, 212)
// Electric Blue: #38BDF8 -> rgb(56, 189, 248)
// Vivid Green: #10B981 -> rgb(16, 185, 129)
// Amber/Gold: #FBBF24 -> rgb(251, 191, 36)
// Coral Red: #F87171 -> rgb(248, 113, 113)
// Charcoal: #111827 -> rgb(17, 24, 39)
// Dark Slate Border: #1E293B -> rgb(30, 41, 59)
// Zero Black: #050505 -> rgb(5, 5, 5)
const (
	Reset     = "\033[0m"
	Bold      = "\033[1m"
	Dim       = "\033[2m"
	Italic    = "\033[3m"
	Underline = "\033[4m"

	// Foregrounds
	FgGhostGreen = "\033[38;2;215;255;224m"
	FgAqua       = "\033[38;2;0;245;212m"
	FgCyan       = "\033[38;2;56;189;248m"
	FgGreen      = "\033[38;2;16;185;129m"
	FgAmber      = "\033[38;2;251;191;36m"
	FgOrange     = "\033[38;2;251;146;60m"
	FgRed        = "\033[38;2;248;113;113m"
	FgWhite      = "\033[38;2;243;244;246m"
	FgMuted      = "\033[38;2;156;163;175m"
	FgMutedGray  = "\033[38;2;156;163;175m"
	FgDarkGray   = "\033[38;2;75;85;99m"
	FgBorder     = "\033[38;2;45;55;72m"
	FgBoxBorder  = "\033[38;2;51;65;85m"

	// Backgrounds
	BgZeroBlack = "\033[48;2;5;5;5m"
	BgCharcoal  = "\033[48;2;17;24;39m"
	BgHeader    = "\033[48;2;15;23;42m"
	BgGreen     = "\033[48;2;16;185;129m"
)

var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

func stripAnsi(str string) string {
	return ansiRegex.ReplaceAllString(str, "")
}

func visualLength(str string) int {
	return utf8.RuneCountInString(stripAnsi(str))
}

// PrintMacWindowHeader renders the Mac terminal dots (● ● ●) and title bar like in the reference image.
func PrintMacWindowHeader(title string) {
	dotRed := "\033[38;2;239;68;68m●"
	dotYellow := "\033[38;2;245;158;11m●"
	dotGreen := "\033[38;2;16;185;129m●"
	fmt.Printf("%s %s %s   %s%s%s%s\n", dotRed, dotYellow, dotGreen, FgMuted, Dim, title, Reset)
}

// PrintBanner renders the branded banner.
func PrintBanner(version string) {
	PrintMacWindowHeader("reconx ~ automated reconnaissance")
	fmt.Printf("%s%s", FgCyan, Bold)
	fmt.Println(`  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗`)
	fmt.Println(`  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝`)
	fmt.Println(`  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝ `)
	fmt.Println(`  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗ `)
	fmt.Println(`  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗`)
	fmt.Println(`  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝`)
	fmt.Print(Reset)
	fmt.Printf("  %s%sAUTOMATED RECONNAISSANCE FRAMEWORK%s                  %sv%s%s\n\n",
		FgGhostGreen, Bold, Reset, FgAqua, version, Reset)
}

// PrintSectionHeader prints a header bar.
func PrintSectionHeader(stepNum, title string) {
	fmt.Printf("\n%s%s[%s]%s %s%s%s\n", FgAqua, Bold, stepNum, Reset, FgWhite, Bold, strings.ToUpper(title))
	fmt.Printf("%s%s%s\n", FgBoxBorder, strings.Repeat("─", 78), Reset)
}

// PrintNotice prints a notice marker.
func PrintNotice(msg string) {
	fmt.Printf("%s%s[*]%s %s%s\n", FgAqua, Bold, Reset, FgWhite, msg)
}

// PrintInfo prints an info marker.
func PrintInfo(msg string) {
	fmt.Printf("%s%s[i]%s %s%s\n", FgCyan, Bold, Reset, FgMuted, msg)
}

// PrintSuccess prints a success indicator.
func PrintSuccess(msg string) {
	fmt.Printf("%s%s[✓]%s %s%s\n", FgGreen, Bold, Reset, FgWhite, msg)
}

// PrintStartupMenu renders Screen 1 from the reference UI: Large stylized ascii title, target info, and numeric menu options.
func PrintStartupMenu(version, targetDomain, mode, outputDir string) {
	PrintMacWindowHeader(fmt.Sprintf("reconx ~ reconx -t %s", targetDomain))
	fmt.Println()

	// Cyan block-gradient ASCII title like in the reference
	fmt.Printf("%s%s", FgCyan, Bold)
	fmt.Println(`  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗`)
	fmt.Println(`  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝`)
	fmt.Println(`  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝ `)
	fmt.Println(`  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗ `)
	fmt.Println(`  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗`)
	fmt.Println(`  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝`)
	fmt.Print(Reset)

	fmt.Printf("  %s%sAUTOMATED RECONNAISSANCE FRAMEWORK%s                  %sv%s%s\n\n",
		FgGhostGreen, Bold, Reset, FgAqua, version, Reset)

	// Target info card with aligned columns
	fmt.Printf("  %sTarget  :%s %s%s%s\n", FgMuted, Reset, FgAqua, targetDomain, Reset)
	fmt.Printf("  %sMode    :%s %s%s%s\n", FgMuted, Reset, FgWhite, mode, Reset)
	fmt.Printf("  %sOutput  :%s %s%s%s\n", FgMuted, Reset, FgWhite, outputDir, Reset)
	fmt.Printf("  %sDate    :%s %s%s%s\n\n", FgMuted, Reset, FgWhite, time.Now().Format("2006-01-02 15:04:05"), Reset)

	fmt.Printf("         %s%s\"Recon today. Own tomorrow.\"%s\n\n", FgMuted, Italic, Reset)

	// Interactive Menu
	fmt.Printf("  %s▶%s %s[1] Start Reconnaissance%s\n", FgAqua, Reset, FgGhostGreen+Bold, Reset)
	fmt.Printf("    %s[2] Enumerate Subdomains Only%s\n", FgWhite, Reset)
	fmt.Printf("    %s[3] Query DNS & Security Records%s\n", FgWhite, Reset)
	fmt.Printf("    %s[4] View Past Scan Drift / Database%s\n", FgWhite, Reset)
	fmt.Printf("    %s[5] Exit%s\n\n", FgRed, Reset)
	fmt.Printf("  %sSelect an option: %s", FgGhostGreen, Reset)
}

// ModuleStatus represents a task in the progress screen (Screen 2).
type ModuleStatus struct {
	Name     string
	Progress int
	Status   string // "done", "running", "pending"
	Icon     string
}

// PrintProgressScreen renders Screen 2 from the reference UI: live progress bars with % and log entries.
func PrintProgressScreen(modules []ModuleStatus, logs []string) {
	fmt.Printf("\n%s%s[+] Running Reconnaissance...%s\n\n", FgAqua, Bold, Reset)

	for _, m := range modules {
		// Progress bar: 18 chars total
		barWidth := 18
		filled := (m.Progress * barWidth) / 100
		if filled > barWidth {
			filled = barWidth
		}
		empty := barWidth - filled

		barColor := FgAqua
		if m.Progress == 100 {
			barColor = FgGreen
		}

		bar := fmt.Sprintf("%s%s%s%s", barColor, strings.Repeat("█", filled), FgDarkGray, strings.Repeat("░", empty))
		icon := m.Icon
		if icon == "" {
			icon = "◎"
		}

		check := fmt.Sprintf("%s…%s", FgMuted, Reset)
		if m.Progress == 100 {
			check = fmt.Sprintf("%s✓%s", FgGreen, Reset)
		}

		fmt.Printf("  %s%s%s  %-24s %s%s  %s%3d%%%s  %s\n",
			FgAqua, icon, Reset, m.Name, bar, Reset, FgGhostGreen, m.Progress, Reset, check)
	}

	fmt.Println()
	if len(logs) > 0 {
		for _, log := range logs {
			fmt.Println("  " + log)
		}
		fmt.Println()
	}
}

// PrintTable renders an elegant modern table matching Screen 3 and 4 in the reference UI.
func PrintTable(headers []string, rows [][]string) {
	FprintTable(os.Stdout, headers, rows)
}

// FprintTable renders the table matching the user's reference mockup.
func FprintTable(w io.Writer, headers []string, rows [][]string) {
	if len(headers) == 0 {
		return
	}

	cols := len(headers)
	colWidths := make([]int, cols)

	for i, h := range headers {
		colWidths[i] = visualLength(h)
	}

	for _, row := range rows {
		for i := 0; i < cols && i < len(row); i++ {
			width := visualLength(row[i])
			if width > colWidths[i] {
				colWidths[i] = width
			}
		}
	}

	// 1. Top border
	fmt.Fprint(w, FgBoxBorder+"┌")
	for i, cw := range colWidths {
		fmt.Fprint(w, strings.Repeat("─", cw+2))
		if i < cols-1 {
			fmt.Fprint(w, "┬")
		} else {
			fmt.Fprint(w, "┐\n")
		}
	}

	// 2. Header row
	fmt.Fprint(w, FgBoxBorder+"│"+Reset)
	for i, h := range headers {
		padding := colWidths[i] - visualLength(h)
		fmt.Fprintf(w, "%s%s %s%s %s%s│%s",
			BgHeader, FgAqua+Bold, h, strings.Repeat(" ", padding), Reset, FgBoxBorder, Reset)
	}
	fmt.Fprintln(w)

	// 3. Header separator
	fmt.Fprint(w, FgBoxBorder+"├")
	for i, cw := range colWidths {
		fmt.Fprint(w, strings.Repeat("─", cw+2))
		if i < cols-1 {
			fmt.Fprint(w, "┼")
		} else {
			fmt.Fprint(w, "┤\n")
		}
	}

	// 4. Data rows
	for rIdx, row := range rows {
		fmt.Fprint(w, FgBoxBorder+"│"+Reset)
		bgStyle := ""
		if rIdx%2 == 1 {
			bgStyle = BgCharcoal
		}

		for i := 0; i < cols; i++ {
			val := ""
			if i < len(row) {
				val = row[i]
			}
			padding := colWidths[i] - visualLength(val)
			if padding < 0 {
				padding = 0
			}

			formattedVal := styleTableCell(val)

			if bgStyle != "" {
				fmt.Fprintf(w, "%s %s%s %s%s│%s",
					bgStyle, formattedVal, strings.Repeat(" ", padding), Reset, FgBoxBorder, Reset)
			} else {
				fmt.Fprintf(w, " %s%s %s│%s",
					formattedVal, strings.Repeat(" ", padding), FgBoxBorder, Reset)
			}
		}
		fmt.Fprintln(w)
	}

	// 5. Bottom border
	fmt.Fprint(w, FgBoxBorder+"└")
	for i, cw := range colWidths {
		fmt.Fprint(w, strings.Repeat("─", cw+2))
		if i < cols-1 {
			fmt.Fprint(w, "┴")
		} else {
			fmt.Fprint(w, "┘\n")
		}
	}
	fmt.Fprint(w, Reset)
}

func styleTableCell(val string) string {
	switch {
	case strings.Contains(val, "[LIVE]"):
		return strings.Replace(val, "[LIVE]", FgGreen+Bold+"200"+Reset, 1)
	case strings.Contains(val, "[OFFLINE]"):
		return strings.Replace(val, "[OFFLINE]", FgRed+"OFFLINE"+Reset, 1)
	case val == "200" || val == "LIVE":
		return FgGreen + Bold + val + Reset
	case val == "403" || val == "401":
		return FgAmber + Bold + val + Reset
	case val == "HIGH" || strings.Contains(val, "High"):
		return FgRed + Bold + val + Reset
	case val == "MEDIUM" || strings.Contains(val, "Medium") || strings.Contains(val, "Moderate"):
		return FgAmber + Bold + val + Reset
	case val == "LOW" || strings.Contains(val, "Low"):
		return FgAqua + val + Reset
	case strings.Contains(val, "Strong"):
		return FgGreen + Bold + val + Reset
	case strings.Contains(val, "NOT CONFIGURED") || strings.Contains(val, "Missing"):
		return FgRed + val + Reset
	case strings.Contains(val, "Cloudflare"):
		return FgAqua + val + Reset
	case strings.Contains(val, "Amazon") || strings.Contains(val, "Google") || strings.Contains(val, "Microsoft"):
		return FgWhite + Bold + val + Reset
	default:
		return FgWhite + val + Reset
	}
}

// PrintSectionTitle prints [ + ] Title (Count) like in Screen 3, 4, 5.
func PrintSectionTitle(title string, count int) {
	if count >= 0 {
		fmt.Printf("\n%s%s[+] %s (%d)%s\n", FgAqua, Bold, title, count, Reset)
	} else {
		fmt.Printf("\n%s%s[+] %s%s\n", FgAqua, Bold, title, Reset)
	}
}

// PrintFindingsTitle prints [ ! ] Findings (Count) like in Screen 5.
func PrintFindingsTitle(title string, count int) {
	fmt.Printf("\n%s%s[!] %s (%d)%s\n", FgRed, Bold, title, count, Reset)
}

// PrintCompletionCard renders Screen 6: The trophy box with aligned summary metrics.
func PrintCompletionCard(target string, subdomains, liveHosts int, duration, outputPath string) {
	w := 64
	fmt.Println()
	fmt.Printf("  %s┌%s┐%s\n", FgGreen, strings.Repeat("─", w), Reset)
	
	headerText := "🏆  Reconnaissance Completed!"
	pad := (w - visualLength(headerText)) / 2
	fmt.Printf("  %s│%s%s%s%s%s%s│%s\n",
		FgGreen, strings.Repeat(" ", pad), FgGhostGreen+Bold, headerText, Reset, strings.Repeat(" ", w-pad-visualLength(headerText)), FgGreen, Reset)
	
	fmt.Printf("  %s│%s│%s\n", FgGreen, strings.Repeat(" ", w), Reset)

	printLine := func(label, val string) {
		content := fmt.Sprintf("    %-18s : %s", label, val)
		rightPad := w - visualLength(content)
		if rightPad < 0 {
			rightPad = 0
		}
		fmt.Printf("  %s│%s%s%s%s%s│%s\n", FgGreen, FgMuted, content, Reset, strings.Repeat(" ", rightPad), FgGreen, Reset)
	}

	printLine("Target", FgAqua+target)
	printLine("Subdomains", fmt.Sprintf("%s%d%s", FgWhite+Bold, subdomains, Reset))
	printLine("Live Active Hosts", fmt.Sprintf("%s%d%s", FgGreen+Bold, liveHosts, Reset))
	printLine("Duration", duration)
	printLine("Output Path", FgAqua+outputPath)

	fmt.Printf("  %s│%s│%s\n", FgGreen, strings.Repeat(" ", w), Reset)
	fmt.Printf("  %s└%s┘%s\n\n", FgGreen, strings.Repeat("─", w), Reset)

	fmt.Printf("         %s%s\"Information is the beginning of security.\"%s\n\n", FgMuted, Italic, Reset)
	fmt.Printf("  %sreconx%s  %sv1.0.0%s  %s│%s  %skeep exploring ...%s\n\n",
		FgGhostGreen+Bold, Reset, FgAqua, Reset, FgDarkGray, Reset, FgMuted, Reset)
}
