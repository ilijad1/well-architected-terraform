// Package firehose contains Well-Architected rules for AWS FIREHOSE resources.
package firehose

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&DeliveryStreamEncryption{})
}

// DeliveryStreamEncryption checks that Kinesis Firehose delivery streams have server-side encryption enabled.
type DeliveryStreamEncryption struct{}

func (r *DeliveryStreamEncryption) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "KDF-001",
		Name:          "Kinesis Firehose Delivery Stream Encryption",
		Description:   "Kinesis Firehose delivery streams should have server-side encryption enabled to protect data in transit.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_kinesis_firehose_delivery_stream"},
		DocURL:        "https://docs.aws.amazon.com/firehose/latest/dev/encryption.html",
	}
}

func (r *DeliveryStreamEncryption) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, sseBlock := range resource.GetBlocks("server_side_encryption") {
		if enabled, ok := sseBlock.GetBoolAttr("enabled"); ok && enabled {
			return nil
		}
	}
	return []model.Finding{{
		RuleID:      "KDF-001",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityHigh,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "Kinesis Firehose delivery stream does not have server-side encryption enabled.",
		Remediation: "Add a server_side_encryption block with enabled = true and optionally specify a key_arn for a customer-managed KMS key.",
		DocURL:      r.Metadata().DocURL,
	}}
}
