// Package report provides output formatters for analysis results.
package report

import (
	"io"
	"sort"

	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// Format represents an output format.
type Format string

const (
	FormatCLI      Format = "cli"
	FormatJSON     Format = "json"
	FormatMarkdown Format = "markdown"
	FormatSARIF    Format = "sarif"
	FormatJUnit    Format = "junit"
	FormatCSV      Format = "csv"
)

// Summary holds the analysis results for report generation.
type Summary struct {
	TotalResources      int                    `json:"total_resources"`
	TotalFindings       int                    `json:"total_findings"`
	SuppressedFindings  int                    `json:"suppressed_findings"`
	ExpiredSuppressions []string               `json:"expired_suppressions,omitempty"`
	BySeverity          map[model.Severity]int `json:"by_severity"`
	ByPillar            map[model.Pillar]int   `json:"by_pillar"`
	Findings            []model.Finding        `json:"findings"`
	RuleMetadata        []model.RuleMetadata   `json:"rule_metadata,omitempty"`
}

// Reporter generates output in a specific format.
type Reporter interface {
	Generate(w io.Writer, summary Summary) error
}

// NewReporter creates a reporter for the given format.
func NewReporter(format Format) Reporter {
	switch format {
	case FormatJSON:
		return &JSONReporter{}
	case FormatMarkdown:
		return &MarkdownReporter{}
	case FormatSARIF:
		return &SARIFReporter{}
	case FormatJUnit:
		return &JUnitReporter{}
	case FormatCSV:
		return &CSVReporter{}
	default:
		return &CLIReporter{}
	}
}

// BuildSummary creates a Summary from resources and findings.
func BuildSummary(resources []model.TerraformResource, findings []model.Finding) Summary {
	summary := Summary{
		TotalResources: len(resources),
		TotalFindings:  len(findings),
		BySeverity:     make(map[model.Severity]int),
		ByPillar:       make(map[model.Pillar]int),
		Findings:       findings,
	}

	for _, f := range findings {
		summary.BySeverity[f.Severity]++
		summary.ByPillar[f.Pillar]++
	}

	// Sort findings by severity (most severe first)
	sort.Slice(summary.Findings, func(i, j int) bool {
		ri := model.SeverityRank(summary.Findings[i].Severity)
		rj := model.SeverityRank(summary.Findings[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return summary.Findings[i].RuleID < summary.Findings[j].RuleID
	})

	return summary
}
