package organizations

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
	"github.com/ilijad1/well-architected-terraform/internal/rules/iam"
)

// SCPWildcardRule checks that SCPs don't have overly permissive Allow statements.
type SCPWildcardRule struct{}

func init() {
	engine.Register(&SCPWildcardRule{})
}

func (r *SCPWildcardRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "ORG-001",
		Name:          "SCP With Wildcard Allow",
		Description:   "Service Control Policies should not have Allow statements with wildcard Action and Resource. This effectively disables the SCP guardrail.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_organizations_policy"},
	}
}

func (r *SCPWildcardRule) Evaluate(resource model.TerraformResource) []model.Finding {
	// Only check SCP type policies
	policyType, _ := resource.GetStringAttr("type")
	if policyType != "" && policyType != "SERVICE_CONTROL_POLICY" {
		return nil
	}

	content, ok := resource.GetStringAttr("content")
	if !ok || content == "" {
		return nil
	}

	doc, err := iam.ParsePolicyJSON(content)
	if err != nil || doc == nil {
		return nil
	}

	for _, stmt := range doc.Statement {
		if stmt.Effect != "Allow" {
			continue
		}

		actions := iam.ActionsFromStatement(stmt)
		resources := iam.ResourcesFromStatement(stmt)

		if iam.ContainsWildcard(actions) && iam.ContainsWildcard(resources) {
			return []model.Finding{{
				RuleID:      "ORG-001",
				RuleName:    "SCP With Wildcard Allow",
				Severity:    model.SeverityHigh,
				Pillar:      model.PillarSecurity,
				Resource:    resource.Address(),
				File:        resource.File,
				Line:        resource.Line,
				Description: "This SCP has an Allow statement with Action \"*\" and Resource \"*\". This makes the SCP a no-op guardrail that allows all actions.",
				Remediation: "Remove the wildcard Allow statement. SCPs should be restrictive — use Deny statements to prevent unauthorized actions.",
			}}
		}
	}

	return nil
}
