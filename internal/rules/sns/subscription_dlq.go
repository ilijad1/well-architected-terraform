package sns

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&SubscriptionDLQRule{})
}

type SubscriptionDLQRule struct{}

func (r *SubscriptionDLQRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "SNS-003",
		Name:          "SNS topic subscription should have a dead-letter queue configured",
		Description:   "Ensures SNS topic subscriptions have a redrive policy with a dead-letter queue for failed message handling.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarReliability,
		ResourceTypes: []string{"aws_sns_topic_subscription"},
		DocURL:        "https://docs.aws.amazon.com/sns/latest/dg/sns-dead-letter-queues.html",
	}
}

func (r *SubscriptionDLQRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	redrivePolicy, exists := resource.GetStringAttr("redrive_policy")
	if !exists || redrivePolicy == "" {
		findings = append(findings, model.Finding{
			RuleID:      "SNS-003",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarReliability,
			Resource:    resource.FullAddress,
			File:        resource.File,
			Line:        resource.Line,
			Description: "SNS topic subscription does not have a redrive policy configured",
			Remediation: "Configure a redrive_policy with a dead-letter queue to handle failed message deliveries",
			DocURL:      r.Metadata().DocURL,
		})
	}

	return findings
}
