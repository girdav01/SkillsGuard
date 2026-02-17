// SkillGuard CLI - VirusTotal for AI Agent Skills.
// Multi-engine security scanner for AI skills, MCP servers, and agentic tools.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/girdav01/skillguard/internal/api"
	"github.com/girdav01/skillguard/internal/core"
	"github.com/girdav01/skillguard/internal/engines"
	"github.com/girdav01/skillguard/internal/intelligence"
	"github.com/girdav01/skillguard/internal/monitoring"
	"github.com/girdav01/skillguard/internal/reporting"
	"github.com/spf13/cobra"
)

var version = "0.3.0"

func main() {
	rootCmd := &cobra.Command{
		Use:     "skillguard",
		Short:   "SkillGuard - VirusTotal for AI Agent Skills",
		Long:    "Multi-engine security scanner for AI skills, MCP servers, and agentic tools.",
		Version: version,
	}

	rootCmd.AddCommand(scanCmd())
	rootCmd.AddCommand(bomCmd())
	rootCmd.AddCommand(monitorCmd())
	rootCmd.AddCommand(rulesCmd())
	rootCmd.AddCommand(serverCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func scanCmd() *cobra.Command {
	var (
		gitURL       string
		outputFormat string
		outputFile   string
		platform     string
		quick        bool
		failOn       string
		rulesDir     string
	)

	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan a skill directory or repository for security issues",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := ""
			if len(args) > 0 {
				path = args[0]
			}
			if path == "" && gitURL == "" {
				return fmt.Errorf("provide a PATH or --git URL to scan")
			}

			scanType := "full"
			if quick {
				scanType = "quick"
			}

			request := core.ScanRequest{
				SkillPath: path,
				GitURL:    gitURL,
				ScanType:  scanType,
				Platform:  core.SkillPlatform(platform),
			}

			result, err := runScan(request, rulesDir)
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}

			switch outputFormat {
			case "json":
				report, err := reporting.GenerateJSONReport(result)
				if err != nil {
					return err
				}
				if outputFile != "" {
					return os.WriteFile(outputFile, []byte(report), 0644)
				}
				fmt.Println(report)
			case "sarif":
				report, err := reporting.GenerateSARIFReport(result)
				if err != nil {
					return err
				}
				if outputFile != "" {
					return os.WriteFile(outputFile, []byte(report), 0644)
				}
				fmt.Println(report)
			case "html":
				report := reporting.GenerateHTMLReport(result)
				out := outputFile
				if out == "" {
					out = "skillguard-report.html"
				}
				if err := os.WriteFile(out, []byte(report), 0644); err != nil {
					return err
				}
				fmt.Printf("HTML report written to %s\n", out)
			default:
				printRichResult(result)
				if outputFile != "" {
					report, _ := reporting.GenerateJSONReport(result)
					os.WriteFile(outputFile, []byte(report), 0644)
					fmt.Printf("\nFull report written to %s\n", outputFile)
				}
			}

			// Exit code based on --fail-on
			if failOn != "" {
				severityOrder := []string{"critical", "high", "medium", "low"}
				thresholdIdx := -1
				for i, s := range severityOrder {
					if s == failOn {
						thresholdIdx = i
						break
					}
				}
				if thresholdIdx >= 0 {
					for _, sev := range severityOrder[:thresholdIdx+1] {
						if count, ok := result.FindingsBySeverity[sev]; ok && count > 0 {
							os.Exit(1)
						}
					}
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&gitURL, "git", "", "Git repository URL to scan")
	cmd.Flags().StringVar(&outputFormat, "format", "rich", "Output format (rich, json, sarif, html)")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write output to file")
	cmd.Flags().StringVar(&platform, "platform", "generic", "Skill platform")
	cmd.Flags().BoolVar(&quick, "quick", false, "Quick scan (hash lookup only)")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "Exit with code 1 if findings at or above this severity")
	cmd.Flags().StringVar(&rulesDir, "rules-dir", "", "Custom rules directory")

	return cmd
}

func bomCmd() *cobra.Command {
	var (
		outputFormat string
		outputFile   string
		includeScan  bool
	)

	cmd := &cobra.Command{
		Use:   "bom <path>",
		Short: "Generate a CycloneDX AI-BOM (SBOM) for a skill package",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]

			var scanResult *core.ScanResult
			if includeScan {
				request := core.NewScanRequest(path)
				var err error
				scanResult, err = runScan(request, "")
				if err != nil {
					return fmt.Errorf("scan failed: %w", err)
				}
				fmt.Printf("Scan complete: %s (score: %d)\n", scanResult.Verdict, scanResult.CompositeScore)
			}

			sbomJSON, err := reporting.GenerateSkillSBOMJSON(path, scanResult)
			if err != nil {
				return fmt.Errorf("SBOM generation failed: %w", err)
			}

			if outputFile != "" {
				if err := os.WriteFile(outputFile, []byte(sbomJSON), 0644); err != nil {
					return err
				}
				fmt.Printf("SBOM written to %s\n", outputFile)
			} else {
				fmt.Println(sbomJSON)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&outputFormat, "format", "cyclonedx", "Output format (cyclonedx, json)")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write SBOM to file")
	cmd.Flags().BoolVar(&includeScan, "include-scan", false, "Run a scan and embed findings in the SBOM")

	return cmd
}

func monitorCmd() *cobra.Command {
	var interval float64

	cmd := &cobra.Command{
		Use:   "monitor <path>",
		Short: "Monitor a skills directory for changes and auto-rescan",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			fmt.Printf("Monitoring %s for changes (polling mode)... (Ctrl+C to stop)\n", path)

			detector := monitoring.NewDriftDetector()
			if err := detector.CaptureBaseline(path); err != nil {
				return fmt.Errorf("failed to capture baseline: %w", err)
			}
			fmt.Println("Baseline captured.")

			for {
				time.Sleep(time.Duration(interval*1000) * time.Millisecond)
				drift := detector.CheckDrift(path)
				if drift.HasDrift {
					fmt.Printf("\nDRIFT DETECTED:\n")
					for _, f := range drift.AddedFiles {
						fmt.Printf("  [added] %s\n", f)
					}
					for _, f := range drift.ModifiedFiles {
						fmt.Printf("  [modified] %s\n", f)
					}
					for _, f := range drift.RemovedFiles {
						fmt.Printf("  [removed] %s\n", f)
					}

					fmt.Println("  Re-scanning...")
					request := core.NewScanRequest(path)
					result, err := runScan(request, "")
					if err != nil {
						fmt.Printf("  Scan error: %v\n", err)
					} else {
						printRichResult(result)
					}
					detector.CaptureBaseline(path)
				}
			}
		},
	}

	cmd.Flags().Float64Var(&interval, "interval", 5.0, "Poll interval in seconds")
	return cmd
}

func rulesCmd() *cobra.Command {
	var category string

	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Manage detection rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Find rules directory relative to executable
			rulesDir := findRulesDir()
			rules, err := core.LoadRules(rulesDir, "", category, true)
			if err != nil {
				return err
			}
			if len(rules) == 0 {
				fmt.Println("No rules found.")
				return nil
			}
			fmt.Printf("Loaded %d rules:\n\n", len(rules))
			for _, rule := range rules {
				fmt.Printf("  [%-8s] %-15s %s\n",
					strings.ToUpper(string(rule.Severity)), rule.ID, rule.Name)
			}
			return nil
		},
	}

	cmd.Flags().BoolP("list", "l", true, "List all detection rules")
	cmd.Flags().StringVar(&category, "category", "", "Filter by category")
	return cmd
}

func serverCmd() *cobra.Command {
	var port int

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Start the SkillGuard API server",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("Starting SkillGuard API server on :%d...\n", port)
			return api.StartServer(port, findRulesDir())
		},
	}

	cmd.Flags().IntVar(&port, "port", 8080, "Server port")
	return cmd
}

func buildEngines(rulesDir string) []core.EngineScanner {
	return []core.EngineScanner{
		engines.NewRegexScanner(rulesDir),
		engines.NewYaraScanner(),
		engines.NewSecretDetector(),
		engines.NewMLClassifier(),
		engines.NewVectorSearchEngine(),
		engines.NewToolPoisoningDetector(),
		engines.NewToolShadowingDetector(),
		engines.NewMCPConfigScanner(),
		engines.NewBehaviorAnalyzer(),
		engines.NewSchemaValidator(),
		engines.NewPermissionAnalyzer(),
		engines.NewObfuscationDetector(),
	}
}

func runScan(request core.ScanRequest, rulesDir string) (*core.ScanResult, error) {
	if rulesDir == "" {
		rulesDir = findRulesDir()
	}
	allEngines := buildEngines(rulesDir)
	threatIntel := intelligence.NewThreatIntelDB()
	orchestrator := core.NewScanOrchestrator(allEngines, threatIntel)
	return orchestrator.Scan(request)
}

func findRulesDir() string {
	// Check relative to CWD
	if info, err := os.Stat("rules"); err == nil && info.IsDir() {
		abs, _ := filepath.Abs("rules")
		return abs
	}
	// Check parent directory (for go-skillguard/cmd/skillguard)
	if info, err := os.Stat("../../rules"); err == nil && info.IsDir() {
		abs, _ := filepath.Abs("../../rules")
		return abs
	}
	// Check alongside executable
	exe, _ := os.Executable()
	if exe != "" {
		dir := filepath.Dir(exe)
		candidate := filepath.Join(dir, "rules")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
		candidate = filepath.Join(dir, "..", "rules")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
	}
	return ""
}

func printRichResult(result *core.ScanResult) {
	verdictStr := string(result.Verdict)
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                    SkillGuard Scan Report                   ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Skill:    %-48s ║\n", result.SkillName)
	fmt.Printf("║  SHA256:   %-48s ║\n", result.SkillSHA256[:16]+"...")
	fmt.Printf("║  Score:    %-48s ║\n", fmt.Sprintf("%d/100", result.CompositeScore))
	fmt.Printf("║  Verdict:  %-48s ║\n", strings.ToUpper(verdictStr))
	fmt.Printf("║  Findings: %-48s ║\n", fmt.Sprintf("%d", result.TotalFindings))
	fmt.Printf("║  Files:    %-48s ║\n", fmt.Sprintf("%d scanned", result.FilesScanned))
	fmt.Printf("║  Engines:  %-48s ║\n", fmt.Sprintf("%d", len(result.EngineResults)))
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")

	if result.TotalFindings > 0 {
		fmt.Println("\nFindings:")
		for _, er := range result.EngineResults {
			for _, f := range er.Findings {
				sevStr := strings.ToUpper(string(f.Severity))
				loc := f.FilePath
				if f.LineStart != nil {
					loc += fmt.Sprintf(":%d", *f.LineStart)
				}
				fmt.Printf("  [%s] %s - %s (%s)\n", sevStr, f.RuleName, f.Description[:min(80, len(f.Description))], loc)
			}
		}
	}

	// Severity breakdown
	if len(result.FindingsBySeverity) > 0 {
		fmt.Println("\nSeverity Breakdown:")
		for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
			if count, ok := result.FindingsBySeverity[sev]; ok && count > 0 {
				fmt.Printf("  %-10s %d\n", strings.ToUpper(sev), count)
			}
		}
	}
}

// Ensure json is used
var _ = json.Marshal
