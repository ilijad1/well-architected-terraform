package cloudtrail

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&LogFileValidation{})
}

type LogFileValidation struct{}

func (r *LogFileValidation) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "CT-003",
		Name:          "CloudTrail Log File Validation",
		Description:   "CloudTrail should have log file validation enabled to detect tampering.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_cloudtrail"},
	}
}

func (r *LogFileValidation) Evaluate(resource model.TerraformResource) []model.Finding {
	enabled, ok := resource.GetBoolAttr("enable_log_file_validation")
	if ok && enabled {
		return nil
	}

	return []model.Finding{{
		RuleID:      "CT-003",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityHigh,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "CloudTrail does not have log file validation enabled.",
		Remediation: "Set enable_log_file_validation = true to detect log file tampering.",
	}}
}
