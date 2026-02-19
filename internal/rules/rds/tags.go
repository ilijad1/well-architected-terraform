package rds

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&InstanceTags{})
}

// InstanceTags checks that RDS instances have tags.
type InstanceTags struct{}

func (r *InstanceTags) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "RDS-006",
		Name:          "RDS Instance Tags",
		Description:   "RDS instances should have tags for cost allocation and resource organization.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarCostOptimization,
		ResourceTypes: []string{"aws_db_instance"},
	}
}

func (r *InstanceTags) Evaluate(resource model.TerraformResource) []model.Finding {
	if _, ok := resource.Attributes["tags"]; ok {
		return nil
	}

	return []model.Finding{{
		RuleID:      "RDS-006",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityLow,
		Pillar:      model.PillarCostOptimization,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "RDS instance does not have tags configured.",
		Remediation: "Add tags to the RDS instance for cost allocation and resource organization.",
	}}
}
