package dynamodb

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
		ID:            "DDB-001",
		Name:          "DynamoDB table should have encryption at rest enabled",
		Description:   "Ensures DynamoDB tables have server-side encryption enabled to protect data at rest",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_dynamodb_table"},
		DocURL:        "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html",
	}
}

func (r *EncryptionRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	if !resource.HasBlock("server_side_encryption") {
		findings = append(findings, model.Finding{
			RuleID:      "DDB-001",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarSecurity,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "DynamoDB table does not have server-side encryption configured",
			Remediation: "Add a server_side_encryption block with enabled = true to encrypt data at rest",
			DocURL:      r.Metadata().DocURL,
		})
		return findings
	}

	// Check if enabled is set to true
	sseBlocks := resource.GetBlocks("server_side_encryption")
	hasEncryption := false

	for _, block := range sseBlocks {
		if enabled, ok := block.GetBoolAttr("enabled"); ok && enabled {
			hasEncryption = true
			break
		}
	}

	if !hasEncryption {
		findings = append(findings, model.Finding{
			RuleID:      "DDB-001",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarSecurity,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "DynamoDB table has server-side encryption disabled",
			Remediation: "Set enabled = true in the server_side_encryption block",
			DocURL:      r.Metadata().DocURL,
		})
	}

	return findings
}
