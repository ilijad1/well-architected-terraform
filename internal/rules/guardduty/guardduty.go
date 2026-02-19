package guardduty

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&DetectorEnabled{})
}

type DetectorEnabled struct{}

func (r *DetectorEnabled) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "GD-001", Name: "GuardDuty Detector Enabled", Description: "GuardDuty detector should be enabled.", Severity: model.SeverityHigh, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_guardduty_detector"}}
}

func (r *DetectorEnabled) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetBoolAttr("enable"); ok && !v {
		return []model.Finding{{RuleID: "GD-001", RuleName: r.Metadata().Name, Severity: model.SeverityHigh, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "GuardDuty detector is disabled.", Remediation: "Set enable = true or remove the attribute (defaults to true)."}}
	}
	return nil
}
