package iam

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// RoleWildcardTrustRule checks that trust policies do not allow Principal: "*" without conditions.
type RoleWildcardTrustRule struct{}

func init() {
	engine.Register(&RoleWildcardTrustRule{})
}

func (r *RoleWildcardTrustRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "IAM-011",
		Name:          "Wildcard Trust Policy",
		Description:   "IAM roles should not have trust policies that allow any AWS principal to assume the role.",
		Severity:      model.SeverityCritical,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_iam_role"},
		ComplianceFrameworks: map[string][]string{
			"CIS": {"1.16"},
		},
	}
}

func (r *RoleWildcardTrustRule) Evaluate(resource model.TerraformResource) []model.Finding {
	policyStr, ok := resource.GetStringAttr("assume_role_policy")
	if !ok || policyStr == "" {
		return nil
	}

	doc, err := ParsePolicyJSON(policyStr)
	if err != nil || doc == nil {
		return nil
	}

	for _, stmt := range doc.Statement {
		if stmt.Effect != "Allow" {
			continue
		}

		principals := PrincipalsFromStatement(stmt)
		for _, p := range principals {
			if p == "*" && stmt.Condition == nil {
				return []model.Finding{{
					RuleID:      "IAM-011",
					RuleName:    "Wildcard Trust Policy",
					Severity:    model.SeverityCritical,
					Pillar:      model.PillarSecurity,
					Resource:    resource.Address(),
					File:        resource.File,
					Line:        resource.Line,
					Description: "This IAM role trust policy allows Principal \"*\" (any AWS account) to assume the role with no conditions. This is a critical security risk.",
					Remediation: "Restrict the Principal to specific AWS account ARNs, service principals, or add conditions to limit who can assume the role.",
				}}
			}
		}
	}

	return nil
}
