package ecs

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&NetworkMode{})
}

type NetworkMode struct{}

func (r *NetworkMode) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "ECS-006",
		Name:          "ECS Task Network Mode",
		Description:   "ECS task definitions should use awsvpc network mode.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_ecs_task_definition"},
	}
}

func (r *NetworkMode) Evaluate(resource model.TerraformResource) []model.Finding {
	mode, ok := resource.GetStringAttr("network_mode")
	if ok && mode == "awsvpc" {
		return nil
	}

	return []model.Finding{{
		RuleID:      "ECS-006",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "ECS task definition does not use awsvpc network mode.",
		Remediation: "Set network_mode = \"awsvpc\" for better network isolation.",
	}}
}
