package secretsmanager

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&SecretTags{})
}

type SecretTags struct{}

func (r *SecretTags) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "SEC-003",
		Name:          "Secrets Manager Secret Tags",
		Description:   "Secrets Manager secrets should have tags for cost allocation and organization.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarCostOptimization,
		ResourceTypes: []string{"aws_secretsmanager_secret"},
	}
}

func (r *SecretTags) Evaluate(resource model.TerraformResource) []model.Finding {
	if _, ok := resource.Attributes["tags"]; ok {
		return nil
	}

	return []model.Finding{{
		RuleID:      "SEC-003",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityLow,
		Pillar:      model.PillarCostOptimization,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "Secrets Manager secret does not have tags configured.",
		Remediation: "Add tags for cost allocation and resource organization.",
	}}
}
