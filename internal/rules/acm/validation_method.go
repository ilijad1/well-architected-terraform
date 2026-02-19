package acm

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// ValidationMethodRule checks that ACM certificates use DNS validation.
type ValidationMethodRule struct{}

func init() {
	engine.Register(&ValidationMethodRule{})
}

func (r *ValidationMethodRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "ACM-001",
		Name:          "ACM Certificate Not Using DNS Validation",
		Description:   "ACM certificates should use DNS validation for reliable, automated renewal.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarOperationalExcellence,
		ResourceTypes: []string{"aws_acm_certificate"},
	}
}

func (r *ValidationMethodRule) Evaluate(resource model.TerraformResource) []model.Finding {
	method, ok := resource.GetStringAttr("validation_method")
	if ok && method == "DNS" {
		return nil
	}

	return []model.Finding{{
		RuleID:      "ACM-001",
		RuleName:    "ACM Certificate Not Using DNS Validation",
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarOperationalExcellence,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "This ACM certificate uses EMAIL validation. DNS validation is more reliable and supports automated renewal without human intervention.",
		Remediation: "Set validation_method = \"DNS\" and create the required Route 53 validation records.",
	}}
}
