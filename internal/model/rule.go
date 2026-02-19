package model

// Rule is the interface every check must implement.
type Rule interface {
	// Metadata returns static information about the rule.
	Metadata() RuleMetadata

	// Evaluate checks a single resource and returns zero or more findings.
	// Returning an empty slice means the resource passed the check.
	Evaluate(resource TerraformResource) []Finding
}

// RuleMetadata describes a rule's identity and classification.
type RuleMetadata struct {
	ID                   string              `json:"id"`
	Name                 string              `json:"name"`
	Description          string              `json:"description"`
	Severity             Severity            `json:"severity"`
	Pillar               Pillar              `json:"pillar"`
	ResourceTypes        []string            `json:"resource_types"`
	DocURL               string              `json:"doc_url,omitempty"`
	ComplianceFrameworks map[string][]string `json:"compliance_frameworks,omitempty"`
}

// CrossResourceRule evaluates findings that require awareness of the full resource set.
// Use this interface when a check cannot be made on a single resource in isolation —
// for example, verifying that every aws_vpc has a corresponding aws_flow_log.
type CrossResourceRule interface {
	Metadata() RuleMetadata
	EvaluateAll(resources []TerraformResource) []Finding
}
