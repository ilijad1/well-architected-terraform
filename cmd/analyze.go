// Package cmd implements the CLI commands for the well-architected-terraform tool.
package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ilijad1/well-architected-terraform/internal/config"
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
	"github.com/ilijad1/well-architected-terraform/internal/parser"
	"github.com/ilijad1/well-architected-terraform/internal/report"
	_ "github.com/ilijad1/well-architected-terraform/internal/rules"
)

var (
	formatFlag      string
	outputFlag      string
	pillarFlag      []string
	minSeverityFlag string
	excludeFlag     []string
	failOnFlag      string
	configFlag      string
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze <plan.json>",
	Short: "Analyze a Terraform plan against AWS Well-Architected Framework",
	Long: `Parse a Terraform plan JSON file and evaluate it against AWS Well-Architected best practices.

Generate the plan JSON with:
  terraform plan -out=plan.bin
  terraform show -json plan.bin > plan.json
  wat analyze plan.json`,
	Args: cobra.ExactArgs(1),
	RunE: runAnalyze,
}

func init() {
	analyzeCmd.Flags().StringVarP(&formatFlag, "format", "f", "cli", "Output format: cli, json, markdown, sarif, junit, csv")
	analyzeCmd.Flags().StringVarP(&outputFlag, "output", "o", "", "Output file path (default: stdout)")
	analyzeCmd.Flags().StringSliceVar(&pillarFlag, "pillar", nil, "Filter by pillar (e.g., Security, Reliability, Sustainability)")
	analyzeCmd.Flags().StringVar(&minSeverityFlag, "min-severity", "", "Minimum severity: CRITICAL, HIGH, MEDIUM, LOW, INFO")
	analyzeCmd.Flags().StringSliceVar(&excludeFlag, "exclude", nil, "Rule IDs to exclude (e.g., S3-005,EC2-006)")
	analyzeCmd.Flags().StringVar(&failOnFlag, "fail-on", "any", "Exit code 1 threshold: CRITICAL, HIGH, MEDIUM, LOW, any, none")
	analyzeCmd.Flags().StringVar(&configFlag, "config", ".wat.yaml", "Path to suppression config file")

	rootCmd.AddCommand(analyzeCmd)
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	planPath := args[0]

	info, err := os.Stat(planPath)
	if err != nil {
		return fmt.Errorf("cannot access plan file %q: %w", planPath, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%q is a directory — wat requires a Terraform plan JSON file\n\nGenerate one with:\n  terraform plan -out=plan.bin\n  terraform show -json plan.bin > plan.json", planPath)
	}

	resources, err := parser.ParsePlanFile(planPath)
	if err != nil {
		return fmt.Errorf("parsing plan file: %w", err)
	}

	if len(resources) == 0 {
		fmt.Fprintln(os.Stderr, "No resources found in plan file", planPath)
		return nil
	}

	// Load suppression config
	cfg, err := config.Load(configFlag)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Build engine config
	engConfig := engine.Config{
		MinSeverity: model.Severity(strings.ToUpper(minSeverityFlag)),
		ExcludeIDs:  excludeFlag,
	}
	for _, p := range pillarFlag {
		engConfig.Pillars = append(engConfig.Pillars, model.Pillar(p))
	}

	// Run analysis
	eng := engine.New(engConfig)
	findings := eng.Analyze(resources)

	// Apply suppressions
	suppResult := config.Apply(findings, cfg.Suppressions, time.Now())

	// Warn about expired suppressions on stderr
	for _, s := range suppResult.ExpiredSuppressions {
		fmt.Fprintf(os.Stderr, "WARN: suppression for %s/%s expired on %s\n", s.RuleID, s.Resource, s.Expires)
	}

	// Build report summary from kept findings
	summary := report.BuildSummary(resources, suppResult.Kept)
	summary.SuppressedFindings = len(suppResult.Suppressed)
	for _, s := range suppResult.ExpiredSuppressions {
		summary.ExpiredSuppressions = append(summary.ExpiredSuppressions, fmt.Sprintf("%s/%s (expired %s)", s.RuleID, s.Resource, s.Expires))
	}

	// Collect rule metadata for SARIF output
	var ruleMeta []model.RuleMetadata
	for _, r := range eng.Rules() {
		ruleMeta = append(ruleMeta, r.Metadata())
	}
	for _, r := range eng.CrossRules() {
		ruleMeta = append(ruleMeta, r.Metadata())
	}
	summary.RuleMetadata = ruleMeta

	reporter := report.NewReporter(report.Format(formatFlag))

	var w io.Writer = os.Stdout
	if outputFlag != "" {
		f, err := os.Create(outputFlag) // #nosec G304 -- path is a CLI argument supplied by the operator
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	if err := reporter.Generate(w, summary); err != nil {
		return fmt.Errorf("generating report: %w", err)
	}

	// Exit with code 1 based on --fail-on threshold (only against kept findings)
	if shouldFail(suppResult.Kept, failOnFlag) {
		os.Exit(1)
	}

	return nil
}

// shouldFail returns true if any finding meets or exceeds the fail-on severity threshold.
func shouldFail(findings []model.Finding, failOn string) bool {
	switch strings.ToUpper(failOn) {
	case "NONE":
		return false
	case "ANY", "INFO":
		return len(findings) > 0
	default:
		threshold := model.Severity(strings.ToUpper(failOn))
		thresholdRank := model.SeverityRank(threshold)
		if thresholdRank == 0 {
			return len(findings) > 0
		}
		for _, f := range findings {
			if model.SeverityRank(f.Severity) >= thresholdRank {
				return true
			}
		}
		return false
	}
}
