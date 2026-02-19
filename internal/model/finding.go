package model

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// SeverityRank returns a numeric rank for sorting (higher = more severe).
func SeverityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

type Pillar string

const (
	PillarOperationalExcellence Pillar = "OperationalExcellence"
	PillarSecurity              Pillar = "Security"
	PillarReliability           Pillar = "Reliability"
	PillarPerformanceEfficiency Pillar = "PerformanceEfficiency"
	PillarCostOptimization      Pillar = "CostOptimization"
	PillarSustainability        Pillar = "Sustainability"
)

// AllPillars returns all Well-Architected pillars.
func AllPillars() []Pillar {
	return []Pillar{
		PillarSecurity,
		PillarReliability,
		PillarOperationalExcellence,
		PillarPerformanceEfficiency,
		PillarCostOptimization,
		PillarSustainability,
	}
}

type Finding struct {
	RuleID      string   `json:"rule_id"`
	RuleName    string   `json:"rule_name"`
	Severity    Severity `json:"severity"`
	Pillar      Pillar   `json:"pillar"`
	Resource    string   `json:"resource"`
	File        string   `json:"file"`
	Line        int      `json:"line"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation"`
	DocURL      string   `json:"doc_url,omitempty"`
}
