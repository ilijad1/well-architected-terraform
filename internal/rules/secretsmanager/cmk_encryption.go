// Package secretsmanager contains Well-Architected rules for AWS SECRETSMANAGER resources.
package secretsmanager

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&CMKEncryption{})
}

type CMKEncryption struct{}

func (r *CMKEncryption) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "SEC-001",
		Name:          "Secrets Manager CMK Encryption",
		Description:   "Secrets Manager secrets should be encrypted with a customer-managed KMS key.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_secretsmanager_secret"},
	}
}

func (r *CMKEncryption) Evaluate(resource model.TerraformResource) []model.Finding {
	kmsKey, ok := resource.GetStringAttr("kms_key_id")
	if ok && kmsKey != "" {
		return nil
	}

	return []model.Finding{{
		RuleID:      "SEC-001",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "Secrets Manager secret is not encrypted with a customer-managed KMS key.",
		Remediation: "Set kms_key_id to a CMK ARN for encryption.",
	}}
}
