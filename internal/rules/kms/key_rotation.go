package kms

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&KeyRotationRule{})
}

type KeyRotationRule struct{}

func (r *KeyRotationRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "KMS-001",
		Name:          "KMS Key Rotation Should Be Enabled",
		Description:   "KMS key should have automatic key rotation enabled for enhanced security.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_kms_key"},
		DocURL:        "https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html",
	}
}

func (r *KeyRotationRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	enableRotation, exists := resource.GetBoolAttr("enable_key_rotation")
	if !exists || !enableRotation {
		findings = append(findings, model.Finding{
			RuleID:      r.Metadata().ID,
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityHigh,
			Pillar:      model.PillarSecurity,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "KMS key does not have automatic key rotation enabled",
			Remediation: "Set enable_key_rotation = true to enable automatic annual key rotation",
			DocURL:      "https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html",
		})
	}

	return findings
}
