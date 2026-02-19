package cloudwatch

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
		ID:            "CW-003",
		Name:          "CloudWatch Log Group Tags",
		Description:   "CloudWatch Log Groups should have tags for cost allocation and resource management",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarCostOptimization,
		ResourceTypes: []string{"aws_cloudwatch_log_group"},
		DocURL:        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html",
	}
}

func (r *TagsRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	if !resource.HasBlock("tags") {
		findings = append(findings, model.Finding{
			RuleID:      "CW-003",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityLow,
			Pillar:      model.PillarCostOptimization,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "CloudWatch Log Group does not have tags configured",
			Remediation: "Add tags block to enable cost allocation and resource management",
		})
	}

	return findings
}
