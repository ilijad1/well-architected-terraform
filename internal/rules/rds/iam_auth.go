package rds

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&IAMAuth{})
}

type IAMAuth struct{}

func (r *IAMAuth) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "RDS-007",
		Name:          "RDS IAM Database Authentication",
		Description:   "RDS instances should have IAM database authentication enabled.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_db_instance"},
	}
}

func (r *IAMAuth) Evaluate(resource model.TerraformResource) []model.Finding {
	enabled, ok := resource.GetBoolAttr("iam_database_authentication_enabled")
	if ok && enabled {
		return nil
	}

	return []model.Finding{{
		RuleID:      "RDS-007",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "RDS instance does not have IAM database authentication enabled.",
		Remediation: "Set iam_database_authentication_enabled = true to use IAM for database authentication.",
	}}
}
