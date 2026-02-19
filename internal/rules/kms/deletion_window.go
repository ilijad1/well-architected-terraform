// Package kms contains Well-Architected rules for AWS KMS resources.
package kms

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&DeletionWindowRule{})
}

type DeletionWindowRule struct{}

func (r *DeletionWindowRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "KMS-002",
		Name:          "KMS Key Deletion Window Should Be At Least 14 Days",
		Description:   "KMS key deletion window should be at least 14 days to allow sufficient time for recovery from accidental deletion.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarReliability,
		ResourceTypes: []string{"aws_kms_key"},
		DocURL:        "https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html",
	}
}

func (r *DeletionWindowRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	// Default is 30 days if not set, so only flag if explicitly set and < 14
	deletionWindow, exists := resource.GetNumberAttr("deletion_window_in_days")
	if exists && deletionWindow < 14 {
		findings = append(findings, model.Finding{
			RuleID:      r.Metadata().ID,
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarReliability,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "KMS key has a deletion window of less than 14 days, which may not provide sufficient time to recover from accidental deletion",
			Remediation: "Set deletion_window_in_days to at least 14 (recommended 30 days)",
			DocURL:      "https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html",
		})
	}

	return findings
}
