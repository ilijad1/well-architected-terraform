package cloudfront

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&CompressionRule{})
}

type CompressionRule struct{}

func (r *CompressionRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "CF-005",
		Name:          "CloudFront Compression",
		Description:   "CloudFront distributions should enable compression for better performance",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarPerformanceEfficiency,
		ResourceTypes: []string{"aws_cloudfront_distribution"},
		DocURL:        "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/ServingCompressedFiles.html",
	}
}

func (r *CompressionRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	if !resource.HasBlock("default_cache_behavior") {
		findings = append(findings, model.Finding{
			RuleID:      "CF-005",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityLow,
			Pillar:      model.PillarPerformanceEfficiency,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "CloudFront distribution does not have a default_cache_behavior block configured",
			Remediation: "Add default_cache_behavior block with compress set to true",
		})
		return findings
	}

	blocks := resource.GetBlocks("default_cache_behavior")
	if len(blocks) > 0 {
		behavior := blocks[0]
		compress, exists := behavior.GetBoolAttr("compress")
		if !exists || !compress {
			findings = append(findings, model.Finding{
				RuleID:      "CF-005",
				RuleName:    r.Metadata().Name,
				Severity:    model.SeverityLow,
				Pillar:      model.PillarPerformanceEfficiency,
				Resource:    resource.Address(),
				File:        resource.File,
				Line:        resource.Line,
				Description: "CloudFront distribution does not have compression enabled",
				Remediation: "Set compress to true in default_cache_behavior block to improve performance",
			})
		}
	}

	return findings
}
