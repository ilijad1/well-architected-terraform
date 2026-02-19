package sqs

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&VisibilityTimeout{})
}

type VisibilityTimeout struct{}

func (r *VisibilityTimeout) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "SQS-004",
		Name:          "SQS Queue Visibility Timeout",
		Description:   "SQS queues should have a visibility timeout of at least 30 seconds.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarReliability,
		ResourceTypes: []string{"aws_sqs_queue"},
	}
}

func (r *VisibilityTimeout) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetNumberAttr("visibility_timeout_seconds"); ok && v >= 30 {
		return nil
	}
	return []model.Finding{{
		RuleID:      "SQS-004",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityLow,
		Pillar:      model.PillarReliability,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "SQS queue visibility timeout is less than 30 seconds",
		Remediation: "Set visibility_timeout_seconds >= 30",
	}}
}
