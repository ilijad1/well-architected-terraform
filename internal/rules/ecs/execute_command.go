package ecs

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&ExecuteCommandLogging{})
}

type ExecuteCommandLogging struct{}

func (r *ExecuteCommandLogging) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "ECS-009", Name: "ECS Execute Command Logging", Description: "ECS clusters should log execute command sessions.", Severity: model.SeverityMedium, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_ecs_cluster"}}
}

func (r *ExecuteCommandLogging) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, cfg := range resource.GetBlocks("configuration") {
		for _, ecc := range cfg.Blocks["execute_command_configuration"] {
			if v, ok := ecc.GetStringAttr("logging"); ok && v != "NONE" {
				return nil
			}
		}
	}
	return []model.Finding{{RuleID: "ECS-009", RuleName: r.Metadata().Name, Severity: model.SeverityMedium, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "ECS cluster does not have execute command logging configured.", Remediation: "Add configuration.execute_command_configuration with logging set to OVERRIDE or DEFAULT."}}
}
