package dynamodb

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&DeletionProtectionRule{})
}

type DeletionProtectionRule struct{}

func (r *DeletionProtectionRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "DDB-003",
		Name:          "DynamoDB table should have deletion protection enabled",
		Description:   "Ensures DynamoDB tables have deletion protection enabled to prevent accidental deletion",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarReliability,
		ResourceTypes: []string{"aws_dynamodb_table"},
		DocURL:        "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/WorkingWithTables.Basics.html#WorkingWithTables.Basics.DeletionProtection",
	}
}

func (r *DeletionProtectionRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	deletionProtection, exists := resource.GetBoolAttr("deletion_protection_enabled")
	if !exists || !deletionProtection {
		findings = append(findings, model.Finding{
			RuleID:      "DDB-003",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarReliability,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "DynamoDB table does not have deletion protection enabled",
			Remediation: "Set deletion_protection_enabled = true to prevent accidental table deletion",
			DocURL:      r.Metadata().DocURL,
		})
	}

	return findings
}
