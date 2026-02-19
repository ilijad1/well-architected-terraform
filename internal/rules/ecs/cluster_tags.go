package ecs

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&ClusterTags{})
}

type ClusterTags struct{}

func (r *ClusterTags) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "ECS-008",
		Name:          "ECS Cluster Tags",
		Description:   "ECS clusters should have tags for cost allocation and organization.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarCostOptimization,
		ResourceTypes: []string{"aws_ecs_cluster"},
	}
}

func (r *ClusterTags) Evaluate(resource model.TerraformResource) []model.Finding {
	if _, ok := resource.Attributes["tags"]; ok {
		return nil
	}

	return []model.Finding{{
		RuleID:      "ECS-008",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityLow,
		Pillar:      model.PillarCostOptimization,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "ECS cluster does not have tags configured.",
		Remediation: "Add tags for cost allocation and resource organization.",
	}}
}
