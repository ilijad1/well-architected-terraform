package cloudtrail

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&EnableLogging{})
}

type EnableLogging struct{}

func (r *EnableLogging) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "CT-005",
		Name:          "CloudTrail Logging Enabled",
		Description:   "CloudTrail logging must not be disabled.",
		Severity:      model.SeverityCritical,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_cloudtrail"},
	}
}

func (r *EnableLogging) Evaluate(resource model.TerraformResource) []model.Finding {
	enabled, ok := resource.GetBoolAttr("enable_logging")
	if ok && !enabled {
		return []model.Finding{{
			RuleID:      "CT-005",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityCritical,
			Pillar:      model.PillarSecurity,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "CloudTrail logging is explicitly disabled.",
			Remediation: "Set enable_logging = true or remove the attribute (defaults to true).",
		}}
	}

	return nil
}
