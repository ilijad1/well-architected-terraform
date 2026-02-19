package networkfirewall

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// LoggingConfigurationRule checks that Network Firewalls have logging configured.
type LoggingConfigurationRule struct{}

func init() {
	engine.RegisterCross(&LoggingConfigurationRule{})
}

func (r *LoggingConfigurationRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "NFW-003",
		Name:          "Network Firewall Missing Logging Configuration",
		Description:   "AWS Network Firewalls should have a logging configuration resource for traffic visibility and incident investigation.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_networkfirewall_firewall", "aws_networkfirewall_logging_configuration"},
	}
}

func (r *LoggingConfigurationRule) EvaluateAll(resources []model.TerraformResource) []model.Finding {
	// Collect firewall ARNs/addresses that have logging configured
	firewallsWithLogging := make(map[string]bool)
	for _, res := range resources {
		if res.Type == "aws_networkfirewall_logging_configuration" {
			fwARN, ok := res.GetStringAttr("firewall_arn")
			if ok {
				firewallsWithLogging[fwARN] = true
			}
		}
	}

	var findings []model.Finding
	for _, res := range resources {
		if res.Type != "aws_networkfirewall_firewall" {
			continue
		}

		fwARN, _ := res.GetStringAttr("arn")
		fwID, _ := res.GetStringAttr("id")

		if !firewallsWithLogging[fwARN] && !firewallsWithLogging[fwID] && !firewallsWithLogging[res.Address()] {
			findings = append(findings, model.Finding{
				RuleID:      "NFW-003",
				RuleName:    "Network Firewall Missing Logging Configuration",
				Severity:    model.SeverityHigh,
				Pillar:      model.PillarSecurity,
				Resource:    res.Address(),
				File:        res.File,
				Line:        res.Line,
				Description: "This Network Firewall has no logging configuration. Without logging, you lose visibility into traffic flow and cannot investigate security incidents.",
				Remediation: "Add an aws_networkfirewall_logging_configuration resource with firewall_arn pointing to this firewall, with ALERT and/or FLOW log types configured.",
			})
		}
	}

	return findings
}
