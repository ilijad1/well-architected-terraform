package cloudfront

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&HTTPSOnlyRule{})
}

type HTTPSOnlyRule struct{}

func (r *HTTPSOnlyRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "CF-002",
		Name:          "CloudFront HTTPS Only",
		Description:   "CloudFront distributions should not allow unencrypted HTTP traffic",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_cloudfront_distribution"},
		DocURL:        "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-viewers-to-cloudfront.html",
	}
}

func (r *HTTPSOnlyRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	if !resource.HasBlock("default_cache_behavior") {
		findings = append(findings, model.Finding{
			RuleID:      "CF-002",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityHigh,
			Pillar:      model.PillarSecurity,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "CloudFront distribution does not have a default_cache_behavior block configured",
			Remediation: "Add default_cache_behavior block with viewer_protocol_policy set to 'https-only' or 'redirect-to-https'",
		})
		return findings
	}

	blocks := resource.GetBlocks("default_cache_behavior")
	if len(blocks) > 0 {
		behavior := blocks[0]
		protocol, exists := behavior.GetStringAttr("viewer_protocol_policy")
		if !exists || protocol == "allow-all" {
			findings = append(findings, model.Finding{
				RuleID:      "CF-002",
				RuleName:    r.Metadata().Name,
				Severity:    model.SeverityHigh,
				Pillar:      model.PillarSecurity,
				Resource:    resource.Address(),
				File:        resource.File,
				Line:        resource.Line,
				Description: "CloudFront distribution allows unencrypted HTTP traffic",
				Remediation: "Set viewer_protocol_policy to 'https-only' or 'redirect-to-https' in default_cache_behavior block",
			})
		}
	}

	return findings
}
