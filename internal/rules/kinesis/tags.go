package kinesis

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
		ID:            "KIN-003",
		Name:          "Kinesis stream should have tags",
		Description:   "Ensures Kinesis streams have tags for cost allocation and resource management.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarCostOptimization,
		ResourceTypes: []string{"aws_kinesis_stream"},
		DocURL:        "https://docs.aws.amazon.com/streams/latest/dev/tagging.html",
	}
}

func (r *TagsRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	// Check if tags attribute exists in the raw attributes map
	tags, exists := resource.Attributes["tags"]
	if !exists {
		findings = append(findings, model.Finding{
			RuleID:      "KIN-003",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityLow,
			Pillar:      model.PillarCostOptimization,
			Resource:    resource.FullAddress,
			File:        resource.File,
			Line:        resource.Line,
			Description: "Kinesis stream does not have tags configured",
			Remediation: "Add tags to the Kinesis stream for cost tracking and resource organization",
			DocURL:      r.Metadata().DocURL,
		})
		return findings
	}

	// Check if tags map is empty
	if tagsMap, ok := tags.(map[string]interface{}); ok {
		if len(tagsMap) == 0 {
			findings = append(findings, model.Finding{
				RuleID:      "KIN-003",
				RuleName:    r.Metadata().Name,
				Severity:    model.SeverityLow,
				Pillar:      model.PillarCostOptimization,
				Resource:    resource.FullAddress,
				File:        resource.File,
				Line:        resource.Line,
				Description: "Kinesis stream has an empty tags map",
				Remediation: "Add meaningful tags to the Kinesis stream for cost tracking and resource organization",
				DocURL:      r.Metadata().DocURL,
			})
		}
	}

	return findings
}
