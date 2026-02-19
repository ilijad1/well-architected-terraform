// Package sqs contains Well-Architected rules for AWS SQS resources.
package sqs

import (
	"encoding/json"
	"strings"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// CrossDLQRule checks that SQS queues with a redrive_policy reference a DLQ
// that is defined within the same Terraform plan.
type CrossDLQRule struct{}

func init() {
	engine.RegisterCross(&CrossDLQRule{})
}

func (r *CrossDLQRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "SQS-005",
		Name:          "SQS Queue DLQ Target Not in Plan",
		Description:   "SQS queues with a redrive_policy should have their dead-letter queue defined in the same Terraform plan for visibility and lifecycle management.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarReliability,
		ResourceTypes: []string{"aws_sqs_queue"},
	}
}

func (r *CrossDLQRule) EvaluateAll(resources []model.TerraformResource) []model.Finding {
	// Collect all SQS queue names and ARNs in the plan
	queueIdentifiers := make(map[string]bool)
	for _, res := range resources {
		if res.Type != "aws_sqs_queue" {
			continue
		}
		name, ok := res.GetStringAttr("name")
		if ok && name != "" {
			queueIdentifiers[name] = true
		}
		queueIdentifiers[res.Name] = true
		queueIdentifiers[res.Address()] = true
	}

	var findings []model.Finding
	for _, res := range resources {
		if res.Type != "aws_sqs_queue" {
			continue
		}

		redriveRaw, ok := res.Attributes["redrive_policy"]
		if !ok || redriveRaw == nil {
			continue
		}

		// redrive_policy is a JSON string
		redriveStr, isStr := redriveRaw.(string)
		if !isStr || redriveStr == "" {
			continue
		}

		// Check if any known queue identifier appears in the redrive policy
		found := false

		// Try to parse as JSON to extract deadLetterTargetArn
		var redriveMap map[string]interface{}
		if err := json.Unmarshal([]byte(redriveStr), &redriveMap); err == nil {
			if dlqArn, ok := redriveMap["deadLetterTargetArn"].(string); ok {
				for id := range queueIdentifiers {
					if id != "" && strings.Contains(dlqArn, id) {
						found = true
						break
					}
				}
			}
		}

		// Fallback: check raw string for any queue identifier
		if !found {
			for id := range queueIdentifiers {
				if id != "" && strings.Contains(redriveStr, id) {
					found = true
					break
				}
			}
		}

		if !found {
			findings = append(findings, model.Finding{
				RuleID:      "SQS-005",
				RuleName:    "SQS Queue DLQ Target Not in Plan",
				Severity:    model.SeverityMedium,
				Pillar:      model.PillarReliability,
				Resource:    res.Address(),
				File:        res.File,
				Line:        res.Line,
				Description: "This SQS queue has a redrive_policy but its dead-letter queue target was not found in the plan. The DLQ may be externally managed or misconfigured.",
				Remediation: "Add an aws_sqs_queue resource for the DLQ and reference it in the redrive_policy. If the DLQ is externally managed, this finding can be suppressed.",
			})
		}
	}

	return findings
}
