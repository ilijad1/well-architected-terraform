package cloudtrail

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&KMSEncryption{})
}

type KMSEncryption struct{}

func (r *KMSEncryption) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "CT-002",
		Name:          "CloudTrail KMS Encryption",
		Description:   "CloudTrail logs should be encrypted with a KMS key.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_cloudtrail"},
	}
}

func (r *KMSEncryption) Evaluate(resource model.TerraformResource) []model.Finding {
	kmsKey, ok := resource.GetStringAttr("kms_key_id")
	if ok && kmsKey != "" {
		return nil
	}

	return []model.Finding{{
		RuleID:      "CT-002",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityHigh,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "CloudTrail logs are not encrypted with a KMS key.",
		Remediation: "Set kms_key_id to a KMS key ARN to encrypt CloudTrail logs.",
	}}
}
