package cloudfront

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&WAFRule{})
}

type WAFRule struct{}

func (r *WAFRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "CF-003",
		Name:          "CloudFront WAF Protection",
		Description:   "CloudFront distributions should have AWS WAF enabled",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_cloudfront_distribution"},
		DocURL:        "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-awswaf.html",
	}
}

func (r *WAFRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	webAclID, exists := resource.GetStringAttr("web_acl_id")
	if !exists || webAclID == "" {
		findings = append(findings, model.Finding{
			RuleID:      "CF-003",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarSecurity,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "CloudFront distribution does not have AWS WAF enabled",
			Remediation: "Set web_acl_id to associate this distribution with a WAF web ACL",
		})
	}

	return findings
}
