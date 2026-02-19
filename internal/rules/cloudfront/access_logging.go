package cloudfront

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&AccessLoggingRule{})
}

type AccessLoggingRule struct{}

func (r *AccessLoggingRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "CF-004",
		Name:          "CloudFront Access Logging",
		Description:   "CloudFront distributions should have access logging enabled",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarOperationalExcellence,
		ResourceTypes: []string{"aws_cloudfront_distribution"},
		DocURL:        "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html",
	}
}

func (r *AccessLoggingRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	if !resource.HasBlock("logging_config") {
		findings = append(findings, model.Finding{
			RuleID:      "CF-004",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarOperationalExcellence,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "CloudFront distribution does not have access logging enabled",
			Remediation: "Add logging_config block to enable access logging",
		})
	}

	return findings
}
