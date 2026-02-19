package rds

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// CrossEventSubscriptionRule checks that the plan includes an
// aws_db_event_subscription that covers failure events for RDS instances/clusters.
type CrossEventSubscriptionRule struct{}

func init() {
	engine.RegisterCross(&CrossEventSubscriptionRule{})
}

func (r *CrossEventSubscriptionRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "RDS-016",
		Name:          "RDS Missing Failure Event Subscription",
		Description:   "RDS instances and clusters should have an aws_db_event_subscription covering failure events to enable proactive alerting on database issues.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarOperationalExcellence,
		ResourceTypes: []string{"aws_db_instance", "aws_rds_cluster", "aws_db_event_subscription"},
	}
}

func (r *CrossEventSubscriptionRule) EvaluateAll(resources []model.TerraformResource) []model.Finding {
	hasFailureSubscription := false
	for _, res := range resources {
		if res.Type == "aws_db_event_subscription" && subscriptionCoversFailures(res) {
			hasFailureSubscription = true
			break
		}
	}

	if hasFailureSubscription {
		return nil
	}

	var findings []model.Finding
	for _, res := range resources {
		if res.Type != "aws_db_instance" && res.Type != "aws_rds_cluster" {
			continue
		}

		findings = append(findings, model.Finding{
			RuleID:      "RDS-016",
			RuleName:    "RDS Missing Failure Event Subscription",
			Severity:    model.SeverityLow,
			Pillar:      model.PillarOperationalExcellence,
			Resource:    res.Address(),
			File:        res.File,
			Line:        res.Line,
			Description: "No aws_db_event_subscription covering failure events was found in the plan. Without failure event notifications, database outages may go undetected.",
			Remediation: "Add an aws_db_event_subscription with event_categories = [\"failure\"] and an sns_topic_arn to receive alerts on database failures.",
		})
	}

	return findings
}

// subscriptionCoversFailures returns true if the event subscription covers failure events
// (either by having no event_categories filter, or by explicitly including "failure").
func subscriptionCoversFailures(res model.TerraformResource) bool {
	cats, ok := res.Attributes["event_categories"]
	if !ok || cats == nil {
		// No filter means all events are subscribed
		return true
	}

	catList, ok := cats.([]interface{})
	if !ok {
		return false
	}

	if len(catList) == 0 {
		return true
	}

	for _, c := range catList {
		if s, ok := c.(string); ok && s == "failure" {
			return true
		}
	}

	return false
}
