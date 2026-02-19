package report

import (
	"fmt"
	"io"

	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// MarkdownReporter outputs findings as a Markdown document.
type MarkdownReporter struct{}

func (r *MarkdownReporter) Generate(w io.Writer, summary Summary) error {
	_, _ = fmt.Fprintln(w, "# AWS Well-Architected Analysis Report")
	_, _ = fmt.Fprintln(w)

	// Summary
	_, _ = fmt.Fprintln(w, "## Summary")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintf(w, "| Metric | Value |\n")
	_, _ = fmt.Fprintf(w, "|--------|-------|\n")
	_, _ = fmt.Fprintf(w, "| Resources Scanned | %d |\n", summary.TotalResources)
	_, _ = fmt.Fprintf(w, "| Total Findings | %d |\n", summary.TotalFindings)
	if summary.SuppressedFindings > 0 {
		_, _ = fmt.Fprintf(w, "| Suppressed Findings | %d |\n", summary.SuppressedFindings)
	}
	_, _ = fmt.Fprintln(w)

	if summary.TotalFindings == 0 {
		_, _ = fmt.Fprintln(w, "No findings. Your Terraform configuration looks good!")
		return nil
	}

	// Severity breakdown
	_, _ = fmt.Fprintln(w, "## Findings by Severity")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "| Severity | Count |")
	_, _ = fmt.Fprintln(w, "|----------|-------|")
	for _, sev := range []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo} {
		if count := summary.BySeverity[sev]; count > 0 {
			_, _ = fmt.Fprintf(w, "| %s | %d |\n", sev, count)
		}
	}
	_, _ = fmt.Fprintln(w)

	// Pillar breakdown
	_, _ = fmt.Fprintln(w, "## Findings by Pillar")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "| Pillar | Count |")
	_, _ = fmt.Fprintln(w, "|--------|-------|")
	for _, pillar := range model.AllPillars() {
		if count := summary.ByPillar[pillar]; count > 0 {
			_, _ = fmt.Fprintf(w, "| %s | %d |\n", pillar, count)
		}
	}
	_, _ = fmt.Fprintln(w)

	// Detailed findings
	_, _ = fmt.Fprintln(w, "## Detailed Findings")
	_, _ = fmt.Fprintln(w)

	for i, f := range summary.Findings {
		_, _ = fmt.Fprintf(w, "### %d. [%s] %s — %s\n\n", i+1, f.RuleID, f.RuleName, f.Severity)
		_, _ = fmt.Fprintf(w, "- **Resource:** `%s`\n", f.Resource)
		_, _ = fmt.Fprintf(w, "- **Location:** `%s:%d`\n", f.File, f.Line)
		_, _ = fmt.Fprintf(w, "- **Pillar:** %s\n", f.Pillar)
		_, _ = fmt.Fprintf(w, "- **Description:** %s\n", f.Description)
		_, _ = fmt.Fprintf(w, "- **Remediation:** %s\n", f.Remediation)
		if f.DocURL != "" {
			_, _ = fmt.Fprintf(w, "- **Documentation:** [AWS Docs](%s)\n", f.DocURL)
		}
		_, _ = fmt.Fprintln(w)
	}

	return nil
}
