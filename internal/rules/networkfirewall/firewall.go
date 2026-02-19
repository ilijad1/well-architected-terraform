// Package networkfirewall contains Well-Architected rules for AWS NETWORKFIREWALL resources.
package networkfirewall

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// DeleteProtectionRule checks that Network Firewalls have delete protection enabled.
type DeleteProtectionRule struct{}

func init() {
	engine.Register(&DeleteProtectionRule{})
}

func (r *DeleteProtectionRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "NFW-001",
		Name:          "Network Firewall Delete Protection Disabled",
		Description:   "AWS Network Firewalls should have delete protection enabled to prevent accidental deletion.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarReliability,
		ResourceTypes: []string{"aws_networkfirewall_firewall"},
	}
}

func (r *DeleteProtectionRule) Evaluate(resource model.TerraformResource) []model.Finding {
	val, ok := resource.GetBoolAttr("delete_protection")
	if ok && val {
		return nil
	}

	return []model.Finding{{
		RuleID:      "NFW-001",
		RuleName:    "Network Firewall Delete Protection Disabled",
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarReliability,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "This Network Firewall does not have delete protection enabled. Accidental deletion could disrupt all VPC traffic inspection.",
		Remediation: "Set delete_protection = true.",
	}}
}

// SubnetChangeProtectionRule checks that subnet change protection is enabled.
type SubnetChangeProtectionRule struct{}

func init() {
	engine.Register(&SubnetChangeProtectionRule{})
}

func (r *SubnetChangeProtectionRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "NFW-002",
		Name:          "Network Firewall Subnet Change Protection Disabled",
		Description:   "AWS Network Firewalls should have subnet change protection enabled.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarReliability,
		ResourceTypes: []string{"aws_networkfirewall_firewall"},
	}
}

func (r *SubnetChangeProtectionRule) Evaluate(resource model.TerraformResource) []model.Finding {
	val, ok := resource.GetBoolAttr("subnet_change_protection")
	if ok && val {
		return nil
	}

	return []model.Finding{{
		RuleID:      "NFW-002",
		RuleName:    "Network Firewall Subnet Change Protection Disabled",
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarReliability,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "This Network Firewall does not have subnet change protection enabled. Accidental subnet modifications could disrupt traffic inspection.",
		Remediation: "Set subnet_change_protection = true.",
	}}
}

// PolicyStatefulRulesRule checks that firewall policies reference stateful rule groups.
type PolicyStatefulRulesRule struct{}

func init() {
	engine.Register(&PolicyStatefulRulesRule{})
}

func (r *PolicyStatefulRulesRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "NFW-004",
		Name:          "Firewall Policy Missing Stateful Rule Groups",
		Description:   "Network Firewall policies should reference stateful rule groups for deep packet inspection.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_networkfirewall_firewall_policy"},
	}
}

func (r *PolicyStatefulRulesRule) Evaluate(resource model.TerraformResource) []model.Finding {
	// Check for stateful_rule_group_reference blocks in the firewall_policy block
	policyBlocks := resource.GetBlocks("firewall_policy")
	for _, pb := range policyBlocks {
		if refs, ok := pb.Blocks["stateful_rule_group_reference"]; ok && len(refs) > 0 {
			return nil
		}
	}

	return []model.Finding{{
		RuleID:      "NFW-004",
		RuleName:    "Firewall Policy Missing Stateful Rule Groups",
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "This Network Firewall policy has no stateful rule group references. Without stateful inspection, the firewall cannot perform deep packet inspection.",
		Remediation: "Add stateful_rule_group_reference blocks to the firewall_policy to enable IDS/IPS and protocol-level inspection.",
	}}
}
