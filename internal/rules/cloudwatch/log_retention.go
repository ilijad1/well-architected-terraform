package cloudwatch

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&LogRetentionRule{})
}

type LogRetentionRule struct{}

func (r *LogRetentionRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "CW-001",
		Name:          "CloudWatch Log Retention",
		Description:   "CloudWatch Log Groups should have retention period configured",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarCostOptimization,
		ResourceTypes: []string{"aws_cloudwatch_log_group"},
		DocURL:        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html#SettingLogRetention",
	}
}

func (r *LogRetentionRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	retention, exists := resource.GetNumberAttr("retention_in_days")
	if !exists || retention <= 0 {
		findings = append(findings, model.Finding{
			RuleID:      "CW-001",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarCostOptimization,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "CloudWatch Log Group does not have retention period configured",
			Remediation: "Set retention_in_days to a positive value to control log retention and costs",
		})
	}

	return findings
}
