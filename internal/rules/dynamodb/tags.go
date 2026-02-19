package dynamodb

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&TagsRule{})
}

type TagsRule struct{}

func (r *TagsRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "DDB-004",
		Name:          "DynamoDB table should have tags",
		Description:   "Ensures DynamoDB tables have tags for better resource management and cost allocation",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarCostOptimization,
		ResourceTypes: []string{"aws_dynamodb_table"},
		DocURL:        "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Tagging.html",
	}
}

func (r *TagsRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	tags, ok := resource.Attributes["tags"].(map[string]interface{})
	if !ok || len(tags) == 0 {
		findings = append(findings, model.Finding{
			RuleID:      "DDB-004",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityLow,
			Pillar:      model.PillarCostOptimization,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "DynamoDB table does not have tags configured",
			Remediation: "Add tags to the DynamoDB table for better resource management and cost tracking",
			DocURL:      r.Metadata().DocURL,
		})
	}

	return findings
}
