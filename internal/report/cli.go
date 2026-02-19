package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// CLIReporter outputs findings as a colored terminal table.
type CLIReporter struct{}

func (r *CLIReporter) Generate(w io.Writer, summary Summary) error {
	if summary.TotalFindings == 0 {
		green := color.New(color.FgGreen, color.Bold)
		green.Fprintln(w, "No findings! Your Terraform configuration looks good.")
		fmt.Fprintf(w, "Scanned %d resources.\n", summary.TotalResources)
		return nil
	}

	// Header
	bold := color.New(color.Bold)
	bold.Fprintf(w, "AWS Well-Architected Analysis Results\n")
	fmt.Fprintf(w, "%s\n\n", strings.Repeat("=", 50))

	// Summary
	fmt.Fprintf(w, "Resources scanned: %d\n", summary.TotalResources)
	fmt.Fprintf(w, "Findings:          %d\n", summary.TotalFindings)
	if summary.SuppressedFindings > 0 {
		fmt.Fprintf(w, "Suppressed:        %d\n", summary.SuppressedFindings)
	}
	fmt.Fprintln(w)

	// Severity breakdown
	bold.Fprintln(w, "By Severity:")
	severities := []model.Severity{
		model.SeverityCritical,
		model.SeverityHigh,
		model.SeverityMedium,
		model.SeverityLow,
		model.SeverityInfo,
	}
	for _, sev := range severities {
		count := summary.BySeverity[sev]
		if count > 0 {
			fmt.Fprintf(w, "  %s %d\n", severityLabel(sev), count)
		}
	}
	fmt.Fprintln(w)

	// Pillar breakdown
	bold.Fprintln(w, "By Pillar:")
	for _, pillar := range model.AllPillars() {
		count := summary.ByPillar[pillar]
		if count > 0 {
			fmt.Fprintf(w, "  %-25s %d\n", pillar, count)
		}
	}
	fmt.Fprintln(w)

	// Findings detail
	bold.Fprintln(w, "Findings:")
	fmt.Fprintf(w, "%s\n", strings.Repeat("-", 80))

	for i, f := range summary.Findings {
		fmt.Fprintf(w, "\n%s [%s] %s\n", severityLabel(f.Severity), f.RuleID, f.RuleName)
		fmt.Fprintf(w, "  Resource:    %s\n", f.Resource)
		fmt.Fprintf(w, "  Location:    %s:%d\n", f.File, f.Line)
		fmt.Fprintf(w, "  Description: %s\n", f.Description)
		fmt.Fprintf(w, "  Remediation: %s\n", f.Remediation)
		if f.DocURL != "" {
			fmt.Fprintf(w, "  Docs:        %s\n", f.DocURL)
		}
		if i < len(summary.Findings)-1 {
			fmt.Fprintf(w, "%s\n", strings.Repeat("-", 80))
		}
	}

	fmt.Fprintln(w)
	return nil
}

func severityLabel(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return color.New(color.FgRed, color.Bold).Sprint("CRITICAL")
	case model.SeverityHigh:
		return color.New(color.FgRed).Sprint("HIGH    ")
	case model.SeverityMedium:
		return color.New(color.FgYellow).Sprint("MEDIUM  ")
	case model.SeverityLow:
		return color.New(color.FgCyan).Sprint("LOW     ")
	case model.SeverityInfo:
		return color.New(color.FgWhite).Sprint("INFO    ")
	default:
		return string(s)
	}
}
