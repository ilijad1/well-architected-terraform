package cloudwatch

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&LogEncryptionRule{})
}

type LogEncryptionRule struct{}

func (r *LogEncryptionRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "CW-002",
		Name:          "CloudWatch Log Encryption",
		Description:   "CloudWatch Log Groups should be encrypted with KMS",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_cloudwatch_log_group"},
		DocURL:        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html",
	}
}

func (r *LogEncryptionRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	kmsKeyID, exists := resource.GetStringAttr("kms_key_id")
	if !exists || kmsKeyID == "" {
		findings = append(findings, model.Finding{
			RuleID:      "CW-002",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarSecurity,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "CloudWatch Log Group is not encrypted with KMS",
			Remediation: "Set kms_key_id to encrypt log data at rest",
		})
	}

	return findings
}
