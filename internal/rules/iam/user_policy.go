package iam

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&UserPolicy{})
}

type UserPolicy struct{}

func (r *UserPolicy) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "IAM-004",
		Name:          "IAM User Inline Policy",
		Description:   "IAM users should not have inline policies attached. Use managed policies instead.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_iam_user_policy"},
	}
}

func (r *UserPolicy) Evaluate(resource model.TerraformResource) []model.Finding {
	return []model.Finding{{
		RuleID:      "IAM-004",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "IAM user has an inline policy attached. Inline policies are harder to manage and audit.",
		Remediation: "Use aws_iam_user_policy_attachment with managed policies instead of inline policies.",
	}}
}
