// Package cloudwatch contains Well-Architected rules for AWS CLOUDWATCH resources.
package cloudwatch

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&AlarmActionsRule{})
}

type AlarmActionsRule struct{}

func (r *AlarmActionsRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "CW-004",
		Name:          "CloudWatch Metric Alarm Actions",
		Description:   "CloudWatch metric alarms should have alarm actions configured.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarOperationalExcellence,
		ResourceTypes: []string{"aws_cloudwatch_metric_alarm"},
	}
}

func (r *AlarmActionsRule) Evaluate(resource model.TerraformResource) []model.Finding {
	if actions, ok := resource.Attributes["alarm_actions"]; ok {
		if list, ok := actions.([]interface{}); ok && len(list) > 0 {
			return nil
		}
	}
	return []model.Finding{{
		RuleID:      "CW-004",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarOperationalExcellence,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "CloudWatch metric alarm does not have alarm actions configured",
		Remediation: "Set alarm_actions to one or more SNS topic ARNs",
	}}
}
