package ecs

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&ContainerInsights{})
}

type ContainerInsights struct{}

func (r *ContainerInsights) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "ECS-001",
		Name:          "ECS Cluster Container Insights",
		Description:   "ECS clusters should have Container Insights enabled for monitoring.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarOperationalExcellence,
		ResourceTypes: []string{"aws_ecs_cluster"},
	}
}

func (r *ContainerInsights) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, setting := range resource.GetBlocks("setting") {
		name, _ := setting.GetStringAttr("name")
		value, _ := setting.GetStringAttr("value")
		if name == "containerInsights" && value == "enabled" {
			return nil
		}
	}

	return []model.Finding{{
		RuleID:      "ECS-001",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarOperationalExcellence,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "ECS cluster does not have Container Insights enabled.",
		Remediation: "Add a setting block with name = \"containerInsights\" and value = \"enabled\".",
	}}
}
