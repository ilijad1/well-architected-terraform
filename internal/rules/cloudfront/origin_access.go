package cloudfront

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&OriginAccess{})
}

type OriginAccess struct{}

func (r *OriginAccess) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "CF-006",
		Name:          "CloudFront Origin Access Control",
		Description:   "CloudFront distributions should use Origin Access Identity or Origin Access Control for S3 origins.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_cloudfront_distribution"},
	}
}

func (r *OriginAccess) Evaluate(resource model.TerraformResource) []model.Finding {
	origins := resource.GetBlocks("origin")
	if len(origins) == 0 {
		return nil
	}
	for _, origin := range origins {
		// Check for OAC
		if v, ok := origin.GetStringAttr("origin_access_control_id"); ok && v != "" {
			continue
		}
		// Check for OAI via s3_origin_config
		if s3Configs, ok := origin.Blocks["s3_origin_config"]; ok && len(s3Configs) > 0 {
			if v, ok := s3Configs[0].GetStringAttr("origin_access_identity"); ok && v != "" {
				continue
			}
		}
		// This origin has neither OAI nor OAC
		return []model.Finding{{
			RuleID:      "CF-006",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityHigh,
			Pillar:      model.PillarSecurity,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "CloudFront distribution has an origin without Origin Access Identity or Origin Access Control",
			Remediation: "Set origin_access_control_id or add s3_origin_config with origin_access_identity",
		}}
	}
	return nil
}
