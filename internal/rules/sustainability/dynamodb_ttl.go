package sustainability

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// DynamoDBTTLRule checks if DynamoDB tables have TTL enabled to reduce storage waste.
type DynamoDBTTLRule struct{}

func init() {
	engine.Register(&DynamoDBTTLRule{})
}

func (r *DynamoDBTTLRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "SUS-010",
		Name:          "DynamoDB Table TTL Not Enabled",
		Description:   "DynamoDB tables should have TTL enabled to automatically expire and delete stale items, reducing storage consumption and cost.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarSustainability,
		ResourceTypes: []string{"aws_dynamodb_table"},
	}
}

func (r *DynamoDBTTLRule) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, block := range resource.GetBlocks("ttl") {
		enabled, ok := block.GetBoolAttr("enabled")
		if ok && enabled {
			return nil
		}
	}

	return []model.Finding{{
		RuleID:      "SUS-010",
		RuleName:    "DynamoDB Table TTL Not Enabled",
		Severity:    model.SeverityLow,
		Pillar:      model.PillarSustainability,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "This DynamoDB table does not have TTL enabled. Without TTL, expired items accumulate indefinitely, wasting storage capacity.",
		Remediation: "Add a ttl block with enabled = true and set the attribute_name to the item attribute that holds the expiry timestamp.",
	}}
}
