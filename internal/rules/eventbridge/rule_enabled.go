package eventbridge

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&RuleEnabled{})
}

// RuleEnabled checks that EventBridge rules are not disabled.
type RuleEnabled struct{}

func (r *RuleEnabled) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "EB-001",
		Name:          "EventBridge Rule Enabled",
		Description:   "EventBridge rules should be in ENABLED state to ensure event-driven automation is active.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarReliability,
		ResourceTypes: []string{"aws_cloudwatch_event_rule"},
		DocURL:        "https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rules.html",
	}
}

func (r *RuleEnabled) Evaluate(resource model.TerraformResource) []model.Finding {
	state, ok := resource.GetStringAttr("state")
	if ok && state == "DISABLED" {
		return []model.Finding{{
			RuleID:      "EB-001",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarReliability,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "EventBridge rule is explicitly disabled (state = \"DISABLED\").",
			Remediation: "Set state = \"ENABLED\" or remove the state attribute (defaults to enabled) to activate the rule.",
			DocURL:      r.Metadata().DocURL,
		}}
	}
	return nil
}
