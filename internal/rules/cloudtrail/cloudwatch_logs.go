// Package cloudtrail contains Well-Architected rules for AWS CLOUDTRAIL resources.
package cloudtrail

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&CloudWatchLogs{})
}

type CloudWatchLogs struct{}

func (r *CloudWatchLogs) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "CT-004",
		Name:          "CloudTrail CloudWatch Logs Integration",
		Description:   "CloudTrail should send logs to CloudWatch for real-time monitoring.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarOperationalExcellence,
		ResourceTypes: []string{"aws_cloudtrail"},
	}
}

func (r *CloudWatchLogs) Evaluate(resource model.TerraformResource) []model.Finding {
	arn, ok := resource.GetStringAttr("cloud_watch_logs_group_arn")
	if ok && arn != "" {
		return nil
	}

	return []model.Finding{{
		RuleID:      "CT-004",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarOperationalExcellence,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "CloudTrail is not configured to send logs to CloudWatch.",
		Remediation: "Set cloud_watch_logs_group_arn to a CloudWatch log group ARN.",
	}}
}
