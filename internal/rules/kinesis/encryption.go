// Package kinesis contains Well-Architected rules for AWS KINESIS resources.
package kinesis

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
		ID:            "KIN-001",
		Name:          "Kinesis stream should use KMS encryption",
		Description:   "Ensures Kinesis streams use KMS encryption to protect data at rest.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_kinesis_stream"},
		DocURL:        "https://docs.aws.amazon.com/streams/latest/dev/server-side-encryption.html",
	}
}

func (r *EncryptionRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	encryptionType, exists := resource.GetStringAttr("encryption_type")
	if !exists || encryptionType != "KMS" {
		findings = append(findings, model.Finding{
			RuleID:      "KIN-001",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityHigh,
			Pillar:      model.PillarSecurity,
			Resource:    resource.FullAddress,
			File:        resource.File,
			Line:        resource.Line,
			Description: "Kinesis stream does not use KMS encryption",
			Remediation: "Set encryption_type to 'KMS' and configure kms_key_id",
			DocURL:      r.Metadata().DocURL,
		})
	}

	return findings
}
