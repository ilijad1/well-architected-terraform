package acm

import (
	"strings"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// TLSPolicyRule checks that HTTPS listeners use modern TLS policies.
type TLSPolicyRule struct{}

func init() {
	engine.Register(&TLSPolicyRule{})
}

func (r *TLSPolicyRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "ACM-003",
		Name:          "HTTPS Listener Using Outdated TLS Policy",
		Description:   "ALB/NLB HTTPS listeners should use a modern TLS security policy.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_lb_listener"},
	}
}

var outdatedTLSPolicies = map[string]bool{
	"ELBSecurityPolicy-2016-08":    true,
	"ELBSecurityPolicy-TLS-1-0-2015-04": true,
	"ELBSecurityPolicy-TLS-1-1-2017-01": true,
	"ELBSecurityPolicy-2015-05":    true,
}

func (r *TLSPolicyRule) Evaluate(resource model.TerraformResource) []model.Finding {
	protocol, _ := resource.GetStringAttr("protocol")
	if strings.ToUpper(protocol) != "HTTPS" && strings.ToUpper(protocol) != "TLS" {
		return nil
	}

	sslPolicy, ok := resource.GetStringAttr("ssl_policy")
	if !ok || sslPolicy == "" || outdatedTLSPolicies[sslPolicy] {
		return []model.Finding{{
			RuleID:      "ACM-003",
			RuleName:    "HTTPS Listener Using Outdated TLS Policy",
			Severity:    model.SeverityHigh,
			Pillar:      model.PillarSecurity,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "This HTTPS listener uses an outdated or missing TLS security policy. Older policies support vulnerable cipher suites.",
			Remediation: "Set ssl_policy to a modern policy such as \"ELBSecurityPolicy-TLS13-1-2-2021-06\" or \"ELBSecurityPolicy-FS-1-2-Res-2020-10\".",
		}}
	}

	return nil
}
