package ecs

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&ResourceLimits{})
}

type ResourceLimits struct{}

func (r *ResourceLimits) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "ECS-007",
		Name:          "ECS Task Resource Limits",
		Description:   "ECS task definitions should have CPU or memory limits set.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarReliability,
		ResourceTypes: []string{"aws_ecs_task_definition"},
	}
}

func (r *ResourceLimits) Evaluate(resource model.TerraformResource) []model.Finding {
	_, hasCPU := resource.Attributes["cpu"]
	_, hasMemory := resource.Attributes["memory"]

	if hasCPU || hasMemory {
		return nil
	}

	return []model.Finding{{
		RuleID:      "ECS-007",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarReliability,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "ECS task definition does not have CPU or memory limits configured.",
		Remediation: "Set cpu and memory attributes on the task definition.",
	}}
}
