package sns

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
		ID:            "SNS-002",
		Name:          "SNS topic should have tags",
		Description:   "Ensures SNS topics have tags for better resource management and cost allocation.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarCostOptimization,
		ResourceTypes: []string{"aws_sns_topic"},
		DocURL:        "https://docs.aws.amazon.com/sns/latest/dg/sns-tags.html",
	}
}

func (r *TagsRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	// Check if tags attribute exists in the raw attributes map
	tags, exists := resource.Attributes["tags"]
	if !exists {
		findings = append(findings, model.Finding{
			RuleID:      "SNS-002",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityLow,
			Pillar:      model.PillarCostOptimization,
			Resource:    resource.FullAddress,
			File:        resource.File,
			Line:        resource.Line,
			Description: "SNS topic does not have tags configured",
			Remediation: "Add tags to the SNS topic for better resource management and cost tracking",
			DocURL:      r.Metadata().DocURL,
		})
		return findings
	}

	// Check if tags map is empty
	if tagsMap, ok := tags.(map[string]interface{}); ok {
		if len(tagsMap) == 0 {
			findings = append(findings, model.Finding{
				RuleID:      "SNS-002",
				RuleName:    r.Metadata().Name,
				Severity:    model.SeverityLow,
				Pillar:      model.PillarCostOptimization,
				Resource:    resource.FullAddress,
				File:        resource.File,
				Line:        resource.Line,
				Description: "SNS topic has an empty tags map",
				Remediation: "Add meaningful tags to the SNS topic for better resource management and cost tracking",
				DocURL:      r.Metadata().DocURL,
			})
		}
	}

	return findings
}
