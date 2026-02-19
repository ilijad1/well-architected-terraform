package sqs

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
		ID:            "SQS-001",
		Name:          "SQS queue should have encryption enabled",
		Description:   "Ensures SQS queues have encryption enabled using either KMS or SQS-managed encryption.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_sqs_queue"},
		DocURL:        "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html",
	}
}

func (r *EncryptionRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	// Check if kms_master_key_id is set
	kmsKeyID, kmsExists := resource.GetStringAttr("kms_master_key_id")
	kmsValid := kmsExists && kmsKeyID != ""

	// Check if sqs_managed_sse_enabled is set to true
	sqsSSE, sqsExists := resource.GetBoolAttr("sqs_managed_sse_enabled")
	sqsValid := sqsExists && sqsSSE

	// At least one encryption method should be enabled
	if !kmsValid && !sqsValid {
		findings = append(findings, model.Finding{
			RuleID:      "SQS-001",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityHigh,
			Pillar:      model.PillarSecurity,
			Resource:    resource.FullAddress,
			File:        resource.File,
			Line:        resource.Line,
			Description: "SQS queue does not have encryption enabled",
			Remediation: "Enable encryption by setting either kms_master_key_id (for KMS encryption) or sqs_managed_sse_enabled = true (for SQS-managed encryption)",
			DocURL:      r.Metadata().DocURL,
		})
	}

	return findings
}
