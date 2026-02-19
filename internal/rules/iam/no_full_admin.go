package iam

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&NoFullAdmin{})
}

// NoFullAdmin checks that IAM policies do not grant full administrator access (Action:* + Resource:*).
type NoFullAdmin struct{}

func (r *NoFullAdmin) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "IAM-006",
		Name:          "IAM Policy No Full Admin Access",
		Description:   "IAM policies should not grant full administrator access by combining Action:* and Resource:*.",
		Severity:      model.SeverityCritical,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_iam_policy", "aws_iam_role_policy", "data.aws_iam_policy_document"},
		DocURL:        "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege",
	}
}

func (r *NoFullAdmin) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	for _, stmt := range resource.GetBlocks("statement") {
		// Skip explicit Deny statements
		if effect, ok := stmt.GetStringAttr("effect"); ok && effect == "Deny" {
			continue
		}

		actions := getListAttr(stmt.Attributes, "actions")
		resources := getListAttr(stmt.Attributes, "resources")

		hasWildcardAction := false
		for _, a := range actions {
			if a == "*" {
				hasWildcardAction = true
				break
			}
		}

		hasWildcardResource := false
		for _, res := range resources {
			if res == "*" {
				hasWildcardResource = true
				break
			}
		}

		if hasWildcardAction && hasWildcardResource {
			findings = append(findings, model.Finding{
				RuleID:      "IAM-006",
				RuleName:    r.Metadata().Name,
				Severity:    model.SeverityCritical,
				Pillar:      model.PillarSecurity,
				Resource:    resource.Address(),
				File:        resource.File,
				Line:        resource.Line,
				Description: "IAM policy statement grants full administrator access (Action: \"*\" and Resource: \"*\").",
				Remediation: "Replace the wildcard with specific actions and resources following the principle of least privilege.",
				DocURL:      r.Metadata().DocURL,
			})
		}
	}

	return findings
}
