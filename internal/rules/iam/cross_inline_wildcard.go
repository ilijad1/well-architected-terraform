package iam

import (
	"strings"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// CrossInlineWildcardRule checks inline policies on roles for wildcard statements.
type CrossInlineWildcardRule struct{}

func init() {
	engine.RegisterCross(&CrossInlineWildcardRule{})
}

func (r *CrossInlineWildcardRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "IAM-014",
		Name:          "Inline Policy With Wildcard Actions",
		Description:   "Inline policies attached to IAM roles should not use wildcard actions. Use managed policies with least-privilege.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_iam_role", "aws_iam_role_policy"},
	}
}

func (r *CrossInlineWildcardRule) EvaluateAll(resources []model.TerraformResource) []model.Finding {
	// Index inline policies by role name
	policyByRole := make(map[string][]model.TerraformResource)
	for _, res := range resources {
		if res.Type == "aws_iam_role_policy" {
			role, ok := res.GetStringAttr("role")
			if ok {
				policyByRole[role] = append(policyByRole[role], res)
			}
		}
	}

	var findings []model.Finding
	for _, res := range resources {
		if res.Type != "aws_iam_role" {
			continue
		}

		// Check inline policies associated with this role
		roleName, _ := res.GetStringAttr("name")
		policies := policyByRole[roleName]

		for _, pol := range policies {
			policyStr, ok := pol.GetStringAttr("policy")
			if !ok || policyStr == "" {
				continue
			}

			doc, err := ParsePolicyJSON(policyStr)
			if err != nil || doc == nil {
				continue
			}

			for _, stmt := range doc.Statement {
				if stmt.Effect != "Allow" {
					continue
				}

				actions := ActionsFromStatement(stmt)
				resources := ResourcesFromStatement(stmt)

				hasWildcardAction := ContainsWildcard(actions)
				hasWildcardResource := ContainsWildcard(resources)

				// Check for service-level wildcards (e.g., "s3:*", "iam:*")
				hasServiceWildcard := false
				for _, a := range actions {
					if strings.HasSuffix(a, ":*") {
						hasServiceWildcard = true
						break
					}
				}

				if (hasWildcardAction || hasServiceWildcard) && hasWildcardResource {
					findings = append(findings, model.Finding{
						RuleID:      "IAM-014",
						RuleName:    "Inline Policy With Wildcard Actions",
						Severity:    model.SeverityHigh,
						Pillar:      model.PillarSecurity,
						Resource:    pol.Address(),
						File:        pol.File,
						Line:        pol.Line,
						Description: "An inline policy on role " + roleName + " grants wildcard actions on wildcard resources. Use managed policies with least-privilege permissions.",
						Remediation: "Replace the inline policy with a managed policy. Scope down Action and Resource to only what is needed.",
					})
				}
			}
		}
	}

	return findings
}
