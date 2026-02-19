package codebuild

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&VPCConfig{})
}

type VPCConfig struct{}

func (r *VPCConfig) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "CB-005", Name: "CodeBuild VPC Configuration", Description: "CodeBuild projects should be configured to run in a VPC.", Severity: model.SeverityLow, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_codebuild_project"}}
}

func (r *VPCConfig) Evaluate(resource model.TerraformResource) []model.Finding {
	if len(resource.GetBlocks("vpc_config")) > 0 {
		return nil
	}
	return []model.Finding{{RuleID: "CB-005", RuleName: r.Metadata().Name, Severity: model.SeverityLow, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "CodeBuild project is not configured to run in a VPC.", Remediation: "Add vpc_config block with vpc_id, subnets, and security_group_ids."}}
}
