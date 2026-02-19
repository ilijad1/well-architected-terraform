package iam

import (
	"fmt"
	"strings"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&WildcardActions{})
}

// WildcardActions checks that IAM policies don't use wildcard actions.
type WildcardActions struct{}

func (r *WildcardActions) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "IAM-001",
		Name:          "IAM Wildcard Actions",
		Description:   "IAM policies should not use wildcard (*) actions, which grant excessive permissions.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_iam_policy", "aws_iam_role_policy", "data.aws_iam_policy_document"},
		DocURL:        "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege",
	}
}

func (r *WildcardActions) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	// Check data.aws_iam_policy_document statement blocks
	for _, stmt := range resource.GetBlocks("statement") {
		actions := getListAttr(stmt.Attributes, "actions")
		for _, action := range actions {
			if action == "*" || strings.HasSuffix(action, ":*") {
				findings = append(findings, model.Finding{
					RuleID:      "IAM-001",
					RuleName:    r.Metadata().Name,
					Severity:    model.SeverityHigh,
					Pillar:      model.PillarSecurity,
					Resource:    resource.Address(),
					File:        resource.File,
					Line:        resource.Line,
					Description: fmt.Sprintf("IAM policy statement uses wildcard action '%s'. This grants overly broad permissions.", action),
					Remediation: "Replace wildcard actions with specific actions needed (e.g., 's3:GetObject' instead of 's3:*').",
					DocURL:      r.Metadata().DocURL,
				})
			}
		}
	}

	return findings
}

func getListAttr(attrs map[string]interface{}, key string) []string {
	val, ok := attrs[key]
	if !ok {
		return nil
	}

	switch v := val.(type) {
	case []interface{}:
		var result []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	case string:
		return []string{v}
	default:
		return nil
	}
}
