package dynamodb

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&KMSCustomerManagedKey{})
}

// KMSCustomerManagedKey checks that DynamoDB tables use a customer-managed KMS key.
type KMSCustomerManagedKey struct{}

func (r *KMSCustomerManagedKey) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "DDB-006",
		Name:          "DynamoDB Table Customer Managed KMS Key",
		Description:   "DynamoDB tables should use a customer-managed KMS key (CMK) for encryption rather than the default AWS-managed key.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_dynamodb_table"},
		DocURL:        "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html",
	}
}

func (r *KMSCustomerManagedKey) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, sseBlock := range resource.GetBlocks("server_side_encryption") {
		if enabled, ok := sseBlock.GetBoolAttr("enabled"); !ok || !enabled {
			break
		}
		kmsKeyARN, ok := sseBlock.GetStringAttr("kms_key_arn")
		if ok && kmsKeyARN != "" {
			return nil
		}
	}
	return []model.Finding{{
		RuleID:      "DDB-006",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "DynamoDB table does not use a customer-managed KMS key for encryption.",
		Remediation: "Add a server_side_encryption block with enabled = true and a kms_key_arn pointing to a customer-managed key.",
		DocURL:      r.Metadata().DocURL,
	}}
}
