package iam

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// RoleTrustExternalIDRule checks that cross-account trust policies require sts:ExternalId.
type RoleTrustExternalIDRule struct{}

func init() {
	engine.Register(&RoleTrustExternalIDRule{})
}

func (r *RoleTrustExternalIDRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "IAM-009",
		Name:          "Cross-Account Trust Missing ExternalId",
		Description:   "IAM roles with cross-account trust policies should require sts:ExternalId to prevent confused deputy attacks.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_iam_role"},
	}
}

func (r *RoleTrustExternalIDRule) Evaluate(resource model.TerraformResource) []model.Finding {
	policyStr, ok := resource.GetStringAttr("assume_role_policy")
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

		principals := PrincipalsFromStatement(stmt)
		hasCrossAccount := false
		for _, p := range principals {
			if isCrossAccountPrincipal(p) && p != "*" {
				hasCrossAccount = true
				break
			}
		}

		if hasCrossAccount && !HasConditionKey(stmt, "sts:ExternalId") {
			findings = append(findings, model.Finding{
				RuleID:      "IAM-009",
				RuleName:    "Cross-Account Trust Missing ExternalId",
				Severity:    model.SeverityHigh,
				Pillar:      model.PillarSecurity,
				Resource:    resource.Address(),
				File:        resource.File,
				Line:        resource.Line,
				Description: "This IAM role has a cross-account trust policy without an sts:ExternalId condition, making it vulnerable to confused deputy attacks.",
				Remediation: "Add a Condition with StringEquals on sts:ExternalId to the trust policy statement.",
			})
		}
	}

	return findings
}
