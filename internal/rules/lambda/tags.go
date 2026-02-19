package lambda

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
		ID:            "LAM-004",
		Name:          "Lambda Function Tags Present",
		Description:   "Ensures Lambda functions have tags for better cost tracking and resource management",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarCostOptimization,
		ResourceTypes: []string{"aws_lambda_function"},
		DocURL:        "https://docs.aws.amazon.com/lambda/latest/dg/configuration-tags.html",
	}
}

func (r *TagsRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	tags, ok := resource.Attributes["tags"].(map[string]interface{})
	if !ok || len(tags) == 0 {
		findings = append(findings, model.Finding{
			RuleID:      "LAM-004",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityLow,
			Pillar:      model.PillarCostOptimization,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "Lambda function does not have any tags defined",
			Remediation: "Add tags to the Lambda function to enable cost tracking, resource organization, and better management. Consider tags like Environment, Owner, Project, and CostCenter",
			DocURL:      r.Metadata().DocURL,
		})
	}

	return findings
}
