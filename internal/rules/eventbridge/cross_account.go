// Package eventbridge contains Well-Architected rules for AWS EVENTBRIDGE resources.
package eventbridge

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&CrossAccountEventBus{})
}

// CrossAccountEventBus checks that EventBridge rules targeting cross-account scenarios
// use a named event bus rather than the default event bus.
type CrossAccountEventBus struct{}

func (r *CrossAccountEventBus) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "EB-002",
		Name:          "EventBridge Rule Uses Named Event Bus",
		Description:   "EventBridge rules should specify a non-default event bus name to avoid mixing security boundaries on the default bus.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_cloudwatch_event_rule"},
		DocURL:        "https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-bus.html",
	}
}

func (r *CrossAccountEventBus) Evaluate(resource model.TerraformResource) []model.Finding {
	busName, ok := resource.GetStringAttr("event_bus_name")
	if !ok || busName == "" || busName == "default" {
		return []model.Finding{{
			RuleID:      "EB-002",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityLow,
			Pillar:      model.PillarSecurity,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "EventBridge rule uses the default event bus. Consider using a custom event bus to isolate event flows.",
			Remediation: "Set event_bus_name to a custom event bus ARN or name for better isolation and security.",
			DocURL:      r.Metadata().DocURL,
		}}
	}
	return nil
}
