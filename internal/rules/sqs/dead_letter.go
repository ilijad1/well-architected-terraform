package sqs

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&DeadLetterRule{})
}

type DeadLetterRule struct{}

func (r *DeadLetterRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "SQS-002",
		Name:          "SQS queue should have a dead-letter queue configured",
		Description:   "Ensures SQS queues have a redrive policy with a dead-letter queue for failed message handling.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarReliability,
		ResourceTypes: []string{"aws_sqs_queue"},
		DocURL:        "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html",
	}
}

func (r *DeadLetterRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	redrivePolicy, exists := resource.GetStringAttr("redrive_policy")
	if !exists || redrivePolicy == "" {
		findings = append(findings, model.Finding{
			RuleID:      "SQS-002",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarReliability,
			Resource:    resource.FullAddress,
			File:        resource.File,
			Line:        resource.Line,
			Description: "SQS queue does not have a redrive policy configured",
			Remediation: "Configure a redrive_policy with a dead-letter queue to handle failed message processing",
			DocURL:      r.Metadata().DocURL,
		})
	}

	return findings
}
