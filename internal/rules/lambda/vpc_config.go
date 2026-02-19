package lambda

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&VPCConfig{})
}

type VPCConfig struct{}

func (r *VPCConfig) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "LAM-005",
		Name:          "Lambda VPC Configuration",
		Description:   "Lambda functions should be configured to run within a VPC.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_lambda_function"},
	}
}

func (r *VPCConfig) Evaluate(resource model.TerraformResource) []model.Finding {
	if resource.HasBlock("vpc_config") {
		return nil
	}

	return []model.Finding{{
		RuleID:      "LAM-005",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "Lambda function is not configured to run within a VPC.",
		Remediation: "Add a vpc_config block with subnet_ids and security_group_ids.",
	}}
}
