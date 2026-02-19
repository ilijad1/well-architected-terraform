package ec2

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&InstanceTags{})
}

// InstanceTags checks that EC2 instances have tags for cost allocation.
type InstanceTags struct{}

func (r *InstanceTags) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "EC2-006",
		Name:          "EC2 Instance Tags",
		Description:   "EC2 instances should have tags for cost allocation and resource organization.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarCostOptimization,
		ResourceTypes: []string{"aws_instance"},
	}
}

func (r *InstanceTags) Evaluate(resource model.TerraformResource) []model.Finding {
	if _, ok := resource.Attributes["tags"]; ok {
		return nil
	}

	return []model.Finding{{
		RuleID:      "EC2-006",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityLow,
		Pillar:      model.PillarCostOptimization,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "EC2 instance does not have tags configured.",
		Remediation: "Add tags to the EC2 instance for cost allocation and resource organization.",
	}}
}
