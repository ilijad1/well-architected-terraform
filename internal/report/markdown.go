package report

import (
	"fmt"
	"io"

	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// MarkdownReporter outputs findings as a Markdown document.
type MarkdownReporter struct{}

func (r *MarkdownReporter) Generate(w io.Writer, summary Summary) error {
	fmt.Fprintln(w, "# AWS Well-Architected Analysis Report")
	fmt.Fprintln(w)

	// Summary
	fmt.Fprintln(w, "## Summary")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "| Metric | Value |\n")
	fmt.Fprintf(w, "|--------|-------|\n")
	fmt.Fprintf(w, "| Resources Scanned | %d |\n", summary.TotalResources)
	fmt.Fprintf(w, "| Total Findings | %d |\n", summary.TotalFindings)
	if summary.SuppressedFindings > 0 {
		fmt.Fprintf(w, "| Suppressed Findings | %d |\n", summary.SuppressedFindings)
	}
	fmt.Fprintln(w)

	if summary.TotalFindings == 0 {
		fmt.Fprintln(w, "No findings. Your Terraform configuration looks good!")
		return nil
	}

	// Severity breakdown
	fmt.Fprintln(w, "## Findings by Severity")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| Severity | Count |")
	fmt.Fprintln(w, "|----------|-------|")
	for _, sev := range []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo} {
		if count := summary.BySeverity[sev]; count > 0 {
			fmt.Fprintf(w, "| %s | %d |\n", sev, count)
		}
	}
	fmt.Fprintln(w)

	// Pillar breakdown
	fmt.Fprintln(w, "## Findings by Pillar")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| Pillar | Count |")
	fmt.Fprintln(w, "|--------|-------|")
	for _, pillar := range model.AllPillars() {
		if count := summary.ByPillar[pillar]; count > 0 {
			fmt.Fprintf(w, "| %s | %d |\n", pillar, count)
		}
	}
	fmt.Fprintln(w)

	// Detailed findings
	fmt.Fprintln(w, "## Detailed Findings")
	fmt.Fprintln(w)

	for i, f := range summary.Findings {
		fmt.Fprintf(w, "### %d. [%s] %s — %s\n\n", i+1, f.RuleID, f.RuleName, f.Severity)
		fmt.Fprintf(w, "- **Resource:** `%s`\n", f.Resource)
		fmt.Fprintf(w, "- **Location:** `%s:%d`\n", f.File, f.Line)
		fmt.Fprintf(w, "- **Pillar:** %s\n", f.Pillar)
		fmt.Fprintf(w, "- **Description:** %s\n", f.Description)
		fmt.Fprintf(w, "- **Remediation:** %s\n", f.Remediation)
		if f.DocURL != "" {
			fmt.Fprintf(w, "- **Documentation:** [AWS Docs](%s)\n", f.DocURL)
		}
		fmt.Fprintln(w)
	}

	return nil
}
