package cloudtrail

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&MultiRegion{})
}

type MultiRegion struct{}

func (r *MultiRegion) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "CT-001",
		Name:          "CloudTrail Multi-Region",
		Description:   "CloudTrail should be enabled in all regions.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_cloudtrail"},
	}
}

func (r *MultiRegion) Evaluate(resource model.TerraformResource) []model.Finding {
	enabled, ok := resource.GetBoolAttr("is_multi_region_trail")
	if ok && enabled {
		return nil
	}

	return []model.Finding{{
		RuleID:      "CT-001",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityHigh,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "CloudTrail is not configured as a multi-region trail.",
		Remediation: "Set is_multi_region_trail = true to capture events from all AWS regions.",
	}}
}
