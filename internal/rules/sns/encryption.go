// Package sns contains Well-Architected rules for AWS SNS resources.
package sns

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&EncryptionRule{})
}

type EncryptionRule struct{}

func (r *EncryptionRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "SNS-001",
		Name:          "SNS topic should have encryption enabled",
		Description:   "Ensures SNS topics have KMS encryption enabled to protect message data.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_sns_topic"},
		DocURL:        "https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html",
	}
}

func (r *EncryptionRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	kmsKeyID, exists := resource.GetStringAttr("kms_master_key_id")
	if !exists || kmsKeyID == "" {
		findings = append(findings, model.Finding{
			RuleID:      "SNS-001",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityHigh,
			Pillar:      model.PillarSecurity,
			Resource:    resource.FullAddress,
			File:        resource.File,
			Line:        resource.Line,
			Description: "SNS topic does not have KMS encryption configured",
			Remediation: "Set kms_master_key_id attribute to a valid KMS key ID or ARN to enable encryption at rest",
			DocURL:      r.Metadata().DocURL,
		})
	}

	return findings
}
