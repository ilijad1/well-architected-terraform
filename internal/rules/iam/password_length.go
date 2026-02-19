package iam

import (
	"fmt"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&PasswordLength{})
}

type PasswordLength struct{}

func (r *PasswordLength) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "IAM-002",
		Name:          "IAM Password Policy Minimum Length",
		Description:   "IAM account password policy should require minimum password length of 14 or more.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_iam_account_password_policy"},
	}
}

func (r *PasswordLength) Evaluate(resource model.TerraformResource) []model.Finding {
	minLen, ok := resource.GetNumberAttr("minimum_password_length")
	if ok && minLen >= 14 {
		return nil
	}

	return []model.Finding{{
		RuleID:      "IAM-002",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityHigh,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: fmt.Sprintf("IAM password policy minimum length is %.0f, should be at least 14.", minLen),
		Remediation: "Set minimum_password_length to at least 14 in the password policy.",
	}}
}
