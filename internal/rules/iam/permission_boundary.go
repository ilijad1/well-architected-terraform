package iam

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// PermissionBoundaryRule checks that IAM roles with broad permissions have a permission boundary.
type PermissionBoundaryRule struct{}

func init() {
	engine.Register(&PermissionBoundaryRule{})
}

func (r *PermissionBoundaryRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "IAM-012",
		Name:          "Role Missing Permission Boundary",
		Description:   "IAM roles should have a permissions boundary to limit the maximum permissions the role can grant.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_iam_role"},
	}
}

func (r *PermissionBoundaryRule) Evaluate(resource model.TerraformResource) []model.Finding {
	boundary, ok := resource.GetStringAttr("permissions_boundary")
	if ok && boundary != "" {
		return nil
	}

	return []model.Finding{{
		RuleID:      "IAM-012",
		RuleName:    "Role Missing Permission Boundary",
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "This IAM role has no permissions boundary set. Permission boundaries provide a safety net that limits the maximum permissions a role can have.",
		Remediation: "Set the permissions_boundary attribute to a managed policy ARN that defines the maximum permissions for this role.",
	}}
}
