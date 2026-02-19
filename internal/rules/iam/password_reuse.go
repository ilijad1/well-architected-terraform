package iam

import (
	"fmt"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&PasswordReuse{})
}

type PasswordReuse struct{}

func (r *PasswordReuse) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "IAM-003",
		Name:          "IAM Password Reuse Prevention",
		Description:   "IAM account password policy should prevent reuse of at least 24 previous passwords.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_iam_account_password_policy"},
	}
}

func (r *PasswordReuse) Evaluate(resource model.TerraformResource) []model.Finding {
	reuse, ok := resource.GetNumberAttr("password_reuse_prevention")
	if ok && reuse >= 24 {
		return nil
	}

	return []model.Finding{{
		RuleID:      "IAM-003",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: fmt.Sprintf("IAM password policy reuse prevention is %.0f, should be at least 24.", reuse),
		Remediation: "Set password_reuse_prevention to at least 24.",
	}}
}
