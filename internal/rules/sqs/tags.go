package sqs

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
		ID:            "SQS-003",
		Name:          "SQS queue should have tags",
		Description:   "Ensures SQS queues have tags for better resource management and cost allocation.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarCostOptimization,
		ResourceTypes: []string{"aws_sqs_queue"},
		DocURL:        "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-queue-tags.html",
	}
}

func (r *TagsRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	// Check if tags attribute exists in the raw attributes map
	tags, exists := resource.Attributes["tags"]
	if !exists {
		findings = append(findings, model.Finding{
			RuleID:      "SQS-003",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityLow,
			Pillar:      model.PillarCostOptimization,
			Resource:    resource.FullAddress,
			File:        resource.File,
			Line:        resource.Line,
			Description: "SQS queue does not have tags configured",
			Remediation: "Add tags to the SQS queue for better resource management and cost tracking",
			DocURL:      r.Metadata().DocURL,
		})
		return findings
	}

	// Check if tags map is empty
	if tagsMap, ok := tags.(map[string]interface{}); ok {
		if len(tagsMap) == 0 {
			findings = append(findings, model.Finding{
				RuleID:      "SQS-003",
				RuleName:    r.Metadata().Name,
				Severity:    model.SeverityLow,
				Pillar:      model.PillarCostOptimization,
				Resource:    resource.FullAddress,
				File:        resource.File,
				Line:        resource.Line,
				Description: "SQS queue has an empty tags map",
				Remediation: "Add meaningful tags to the SQS queue for better resource management and cost tracking",
				DocURL:      r.Metadata().DocURL,
			})
		}
	}

	return findings
}
