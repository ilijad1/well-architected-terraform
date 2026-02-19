package s3

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
		ID:            "S3-006",
		Name:          "S3 KMS Encryption with CMK",
		Description:   "S3 bucket encryption should use aws:kms with a customer-managed KMS key.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_s3_bucket_server_side_encryption_configuration"},
	}
}

func (r *KMSEncryption) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, rule := range resource.GetBlocks("rule") {
		for _, sse := range rule.Blocks["apply_server_side_encryption_by_default"] {
			algo, _ := sse.GetStringAttr("sse_algorithm")
			keyID, hasKey := sse.GetStringAttr("kms_master_key_id")
			if algo == "aws:kms" && hasKey && keyID != "" {
				return nil
			}
		}
	}

	return []model.Finding{{
		RuleID:      "S3-006",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "S3 bucket encryption is not configured with aws:kms and a customer-managed KMS key.",
		Remediation: "Set sse_algorithm to 'aws:kms' and specify a kms_master_key_id.",
	}}
}
