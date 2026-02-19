// Package organizations contains Well-Architected rules for AWS ORGANIZATIONS resources.
package organizations

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// OUNoSCPRule checks that organizational units have at least one SCP attached.
type OUNoSCPRule struct{}

func init() {
	engine.RegisterCross(&OUNoSCPRule{})
}

func (r *OUNoSCPRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "ORG-003",
		Name:          "Organizational Unit Without SCP",
		Description:   "Organizational units should have at least one SCP attached to enforce guardrails on member accounts.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_organizations_organizational_unit", "aws_organizations_policy_attachment"},
	}
}

func (r *OUNoSCPRule) EvaluateAll(resources []model.TerraformResource) []model.Finding {
	// Collect target IDs that have policy attachments
	targetsWithSCP := make(map[string]bool)
	for _, res := range resources {
		if res.Type == "aws_organizations_policy_attachment" {
			targetID, ok := res.GetStringAttr("target_id")
			if ok {
				targetsWithSCP[targetID] = true
			}
		}
	}

	var findings []model.Finding
	for _, res := range resources {
		if res.Type != "aws_organizations_organizational_unit" {
			continue
		}

		ouID, _ := res.GetStringAttr("id")
		if !targetsWithSCP[ouID] && !targetsWithSCP[res.Address()] {
			findings = append(findings, model.Finding{
				RuleID:      "ORG-003",
				RuleName:    "Organizational Unit Without SCP",
				Severity:    model.SeverityMedium,
				Pillar:      model.PillarSecurity,
				Resource:    res.Address(),
				File:        res.File,
				Line:        res.Line,
				Description: "This organizational unit has no SCP attached. Without SCPs, member accounts have no guardrails preventing unintended actions.",
				Remediation: "Attach at least one SCP to this OU via aws_organizations_policy_attachment to enforce security boundaries.",
			})
		}
	}

	return findings
}
