package iam

import (
	"strings"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// CrossAdminAttachmentRule detects AdministratorAccess policy attachments.
type CrossAdminAttachmentRule struct{}

func init() {
	engine.RegisterCross(&CrossAdminAttachmentRule{})
}

func (r *CrossAdminAttachmentRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:          "IAM-013",
		Name:        "AdministratorAccess Policy Attached",
		Description: "The AdministratorAccess managed policy should not be attached to roles or users. Use least-privilege policies instead.",
		Severity:    model.SeverityCritical,
		Pillar:      model.PillarSecurity,
		ResourceTypes: []string{
			"aws_iam_role_policy_attachment",
			"aws_iam_user_policy_attachment",
			"aws_iam_group_policy_attachment",
		},
		ComplianceFrameworks: map[string][]string{
			"CIS": {"1.16"},
		},
	}
}

func (r *CrossAdminAttachmentRule) EvaluateAll(resources []model.TerraformResource) []model.Finding {
	var findings []model.Finding

	for _, res := range resources {
		switch res.Type {
		case "aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment", "aws_iam_group_policy_attachment":
			arn, ok := res.GetStringAttr("policy_arn")
			if !ok {
				continue
			}
			if isAdminPolicy(arn) {
				findings = append(findings, model.Finding{
					RuleID:      "IAM-013",
					RuleName:    "AdministratorAccess Policy Attached",
					Severity:    model.SeverityCritical,
					Pillar:      model.PillarSecurity,
					Resource:    res.Address(),
					File:        res.File,
					Line:        res.Line,
					Description: "The AdministratorAccess managed policy is attached. This grants unrestricted access to all AWS services and resources.",
					Remediation: "Replace AdministratorAccess with a least-privilege policy that grants only the permissions needed.",
				})
			}
		}
	}

	return findings
}

func isAdminPolicy(arn string) bool {
	adminPolicies := []string{
		"AdministratorAccess",
		"arn:aws:iam::aws:policy/AdministratorAccess",
	}
	for _, admin := range adminPolicies {
		if strings.Contains(arn, admin) {
			return true
		}
	}
	return false
}
