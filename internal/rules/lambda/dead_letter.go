// Package lambda contains rules for AWS Lambda resources.
package lambda

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
		ID:            "LAM-002",
		Name:          "Lambda Dead Letter Queue Configured",
		Description:   "Ensures Lambda functions have a dead letter queue configured for failed executions",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarReliability,
		ResourceTypes: []string{"aws_lambda_function"},
		DocURL:        "https://docs.aws.amazon.com/lambda/latest/dg/invocation-async.html#invocation-dlq",
	}
}

func (r *DeadLetterRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	if !resource.HasBlock("dead_letter_config") {
		findings = append(findings, model.Finding{
			RuleID:      "LAM-002",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarReliability,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "Lambda function does not have a dead letter queue configured",
			Remediation: "Add a dead_letter_config block with target_arn pointing to an SQS queue or SNS topic to handle failed asynchronous invocations",
			DocURL:      r.Metadata().DocURL,
		})
	}

	return findings
}
