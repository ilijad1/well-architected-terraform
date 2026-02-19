package organizations

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// SCPUnattachedRule checks that SCPs are attached to at least one OU or account.
type SCPUnattachedRule struct{}

func init() {
	engine.RegisterCross(&SCPUnattachedRule{})
}

func (r *SCPUnattachedRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "ORG-002",
		Name:          "SCP Not Attached to Any Target",
		Description:   "Service Control Policies should be attached to at least one organizational unit or account to have any effect.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_organizations_policy", "aws_organizations_policy_attachment"},
	}
}

func (r *SCPUnattachedRule) EvaluateAll(resources []model.TerraformResource) []model.Finding {
	// Collect policy IDs/addresses that have attachments
	attachedPolicies := make(map[string]bool)
	for _, res := range resources {
		if res.Type == "aws_organizations_policy_attachment" {
			policyID, ok := res.GetStringAttr("policy_id")
			if ok {
				attachedPolicies[policyID] = true
			}
		}
	}

	var findings []model.Finding
	for _, res := range resources {
		if res.Type != "aws_organizations_policy" {
			continue
		}

		// Only check SCPs
		policyType, _ := res.GetStringAttr("type")
		if policyType != "" && policyType != "SERVICE_CONTROL_POLICY" {
			continue
		}

		policyID, _ := res.GetStringAttr("id")
		if !attachedPolicies[policyID] && !attachedPolicies[res.Address()] {
			findings = append(findings, model.Finding{
				RuleID:      "ORG-002",
				RuleName:    "SCP Not Attached to Any Target",
				Severity:    model.SeverityMedium,
				Pillar:      model.PillarSecurity,
				Resource:    res.Address(),
				File:        res.File,
				Line:        res.Line,
				Description: "This Service Control Policy is not attached to any organizational unit or account. An unattached SCP provides no guardrails.",
				Remediation: "Add an aws_organizations_policy_attachment resource to attach this SCP to the relevant OUs or accounts.",
			})
		}
	}

	return findings
}
