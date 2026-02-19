// Package waf contains Well-Architected rules for AWS WAF resources.
package waf

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&RateBasedRule{})
}

// RateBasedRule checks that WAFv2 web ACLs include at least one rate-based rule for DDoS protection.
type RateBasedRule struct{}

func (r *RateBasedRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "WAF-004",
		Name:          "WAF Rate-Based Rule",
		Description:   "WAFv2 web ACLs should include at least one rate-based rule to protect against DDoS and brute-force attacks.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_wafv2_web_acl"},
		DocURL:        "https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based.html",
	}
}

func (r *RateBasedRule) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, ruleBlock := range resource.GetBlocks("rule") {
		for _, stmt := range ruleBlock.Blocks["statement"] {
			if _, ok := stmt.Blocks["rate_based_statement"]; ok {
				return nil
			}
		}
	}
	return []model.Finding{{
		RuleID:      "WAF-004",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "WAF web ACL does not include a rate-based rule, leaving it vulnerable to DDoS and brute-force attacks.",
		Remediation: "Add a rule with a rate_based_statement to limit request rates from individual IP addresses.",
		DocURL:      r.Metadata().DocURL,
	}}
}
