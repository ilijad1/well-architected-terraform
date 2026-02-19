package iam

import (
	"strings"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// PassRoleConditionRule checks that iam:PassRole has an iam:PassedToService condition.
type PassRoleConditionRule struct{}

func init() {
	engine.Register(&PassRoleConditionRule{})
}

func (r *PassRoleConditionRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "IAM-010",
		Name:          "iam:PassRole Without Condition",
		Description:   "iam:PassRole without an iam:PassedToService condition allows privilege escalation.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_iam_policy", "aws_iam_role_policy"},
	}
}

func (r *PassRoleConditionRule) Evaluate(resource model.TerraformResource) []model.Finding {
	policyStr, ok := resource.GetStringAttr("policy")
	if !ok || policyStr == "" {
		return nil
	}

	doc, err := ParsePolicyJSON(policyStr)
	if err != nil || doc == nil {
		return nil
	}

	var findings []model.Finding
	for _, stmt := range doc.Statement {
		if stmt.Effect != "Allow" {
			continue
		}

		actions := ActionsFromStatement(stmt)
		hasPassRole := false
		for _, a := range actions {
			lower := strings.ToLower(a)
			if lower == "iam:passrole" || lower == "iam:*" || lower == "*" {
				hasPassRole = true
				break
			}
		}

		if hasPassRole && !HasConditionKey(stmt, "iam:PassedToService") {
			findings = append(findings, model.Finding{
				RuleID:      "IAM-010",
				RuleName:    "iam:PassRole Without Condition",
				Severity:    model.SeverityHigh,
				Pillar:      model.PillarSecurity,
				Resource:    resource.Address(),
				File:        resource.File,
				Line:        resource.Line,
				Description: "This policy grants iam:PassRole without constraining which services can receive the role via iam:PassedToService condition.",
				Remediation: "Add a Condition with StringEquals on iam:PassedToService to limit which services this role can be passed to.",
			})
		}
	}

	return findings
}
