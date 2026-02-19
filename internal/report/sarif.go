package report

import (
	"encoding/json"
	"io"

	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// SARIF 2.1.0 output structs.

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string                     `json:"name"`
	InformationURI string                     `json:"informationUri,omitempty"`
	Version        string                     `json:"version,omitempty"`
	Rules          []sarifReportingDescriptor `json:"rules,omitempty"`
}

type sarifReportingDescriptor struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription sarifMessage      `json:"shortDescription"`
	HelpURI          string            `json:"helpUri,omitempty"`
	Properties       map[string]interface{} `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// SARIFReporter outputs findings in SARIF 2.1.0 JSON format.
type SARIFReporter struct{}

func (r *SARIFReporter) Generate(w io.Writer, summary Summary) error {
	// Build rule descriptors from metadata
	ruleIndex := make(map[string]bool)
	var rules []sarifReportingDescriptor
	for _, m := range summary.RuleMetadata {
		if ruleIndex[m.ID] {
			continue
		}
		ruleIndex[m.ID] = true
		rd := sarifReportingDescriptor{
			ID:               m.ID,
			Name:             m.Name,
			ShortDescription: sarifMessage{Text: m.Description},
			HelpURI:          m.DocURL,
		}
		if len(m.ComplianceFrameworks) > 0 {
			rd.Properties = map[string]interface{}{
				"complianceFrameworks": m.ComplianceFrameworks,
			}
		}
		rules = append(rules, rd)
	}

	// Also add rule descriptors for any findings whose rules aren't in RuleMetadata
	for _, f := range summary.Findings {
		if ruleIndex[f.RuleID] {
			continue
		}
		ruleIndex[f.RuleID] = true
		rules = append(rules, sarifReportingDescriptor{
			ID:               f.RuleID,
			Name:             f.RuleName,
			ShortDescription: sarifMessage{Text: f.Description},
			HelpURI:          f.DocURL,
		})
	}

	var results []sarifResult
	for _, f := range summary.Findings {
		result := sarifResult{
			RuleID:  f.RuleID,
			Level:   severityToSARIFLevel(f.Severity),
			Message: sarifMessage{Text: f.Description + " Remediation: " + f.Remediation},
		}
		if f.File != "" {
			loc := sarifLocation{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: f.File},
				},
			}
			if f.Line > 0 {
				loc.PhysicalLocation.Region = &sarifRegion{StartLine: f.Line}
			}
			result.Locations = []sarifLocation{loc}
		}
		results = append(results, result)
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:  "wat",
					Rules: rules,
				},
			},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func severityToSARIFLevel(s model.Severity) string {
	switch s {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	case model.SeverityLow, model.SeverityInfo:
		return "note"
	default:
		return "none"
	}
}
