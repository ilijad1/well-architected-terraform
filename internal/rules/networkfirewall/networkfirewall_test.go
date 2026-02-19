package networkfirewall

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func res(resType, name string, attrs map[string]interface{}) model.TerraformResource {
	return model.TerraformResource{
		Type:       resType,
		Name:       name,
		Attributes: attrs,
		Blocks:     map[string][]model.Block{},
	}
}

func resWithBlocks(resType, name string, attrs map[string]interface{}, blocks map[string][]model.Block) model.TerraformResource {
	return model.TerraformResource{
		Type:       resType,
		Name:       name,
		Attributes: attrs,
		Blocks:     blocks,
	}
}

// --- NFW-001: Delete Protection ---

func TestDeleteProtection_Disabled(t *testing.T) {
	r := &DeleteProtectionRule{}
	findings := r.Evaluate(res("aws_networkfirewall_firewall", "fw", map[string]interface{}{
		"delete_protection": false,
	}))
	assert.Len(t, findings, 1)
	assert.Equal(t, "NFW-001", findings[0].RuleID)
}

func TestDeleteProtection_Enabled(t *testing.T) {
	r := &DeleteProtectionRule{}
	findings := r.Evaluate(res("aws_networkfirewall_firewall", "fw", map[string]interface{}{
		"delete_protection": true,
	}))
	assert.Empty(t, findings)
}

func TestDeleteProtection_NotSet(t *testing.T) {
	r := &DeleteProtectionRule{}
	findings := r.Evaluate(res("aws_networkfirewall_firewall", "fw", map[string]interface{}{}))
	assert.Len(t, findings, 1)
}

// --- NFW-002: Subnet Change Protection ---

func TestSubnetChangeProtection_Disabled(t *testing.T) {
	r := &SubnetChangeProtectionRule{}
	findings := r.Evaluate(res("aws_networkfirewall_firewall", "fw", map[string]interface{}{
		"subnet_change_protection": false,
	}))
	assert.Len(t, findings, 1)
	assert.Equal(t, "NFW-002", findings[0].RuleID)
}

func TestSubnetChangeProtection_Enabled(t *testing.T) {
	r := &SubnetChangeProtectionRule{}
	findings := r.Evaluate(res("aws_networkfirewall_firewall", "fw", map[string]interface{}{
		"subnet_change_protection": true,
	}))
	assert.Empty(t, findings)
}

// --- NFW-003: Logging Configuration ---

func TestLoggingConfiguration_Missing(t *testing.T) {
	r := &LoggingConfigurationRule{}
	resources := []model.TerraformResource{
		res("aws_networkfirewall_firewall", "fw", map[string]interface{}{}),
	}
	findings := r.EvaluateAll(resources)
	assert.Len(t, findings, 1)
	assert.Equal(t, "NFW-003", findings[0].RuleID)
}

func TestLoggingConfiguration_Present(t *testing.T) {
	r := &LoggingConfigurationRule{}
	fw := res("aws_networkfirewall_firewall", "fw", map[string]interface{}{
		"arn": "arn:aws:network-firewall:us-east-1:123456789012:firewall/fw",
	})
	logging := res("aws_networkfirewall_logging_configuration", "fw_logging", map[string]interface{}{
		"firewall_arn": "arn:aws:network-firewall:us-east-1:123456789012:firewall/fw",
	})
	findings := r.EvaluateAll([]model.TerraformResource{fw, logging})
	assert.Empty(t, findings)
}

func TestLoggingConfiguration_WrongFirewall(t *testing.T) {
	r := &LoggingConfigurationRule{}
	fw := res("aws_networkfirewall_firewall", "fw", map[string]interface{}{
		"arn": "arn:aws:network-firewall:us-east-1:123456789012:firewall/fw-a",
	})
	logging := res("aws_networkfirewall_logging_configuration", "other_logging", map[string]interface{}{
		"firewall_arn": "arn:aws:network-firewall:us-east-1:123456789012:firewall/fw-b",
	})
	findings := r.EvaluateAll([]model.TerraformResource{fw, logging})
	assert.Len(t, findings, 1)
}

// --- NFW-004: Policy Stateful Rules ---

func TestPolicyStatefulRules_Missing(t *testing.T) {
	r := &PolicyStatefulRulesRule{}
	findings := r.Evaluate(resWithBlocks("aws_networkfirewall_firewall_policy", "policy",
		map[string]interface{}{},
		map[string][]model.Block{
			"firewall_policy": {{
				Type:       "firewall_policy",
				Attributes: map[string]interface{}{},
				Blocks:     map[string][]model.Block{},
			}},
		},
	))
	assert.Len(t, findings, 1)
	assert.Equal(t, "NFW-004", findings[0].RuleID)
}

func TestPolicyStatefulRules_Present(t *testing.T) {
	r := &PolicyStatefulRulesRule{}
	findings := r.Evaluate(resWithBlocks("aws_networkfirewall_firewall_policy", "policy",
		map[string]interface{}{},
		map[string][]model.Block{
			"firewall_policy": {{
				Type:       "firewall_policy",
				Attributes: map[string]interface{}{},
				Blocks: map[string][]model.Block{
					"stateful_rule_group_reference": {{
						Type:       "stateful_rule_group_reference",
						Attributes: map[string]interface{}{"resource_arn": "arn:aws:..."},
					}},
				},
			}},
		},
	))
	assert.Empty(t, findings)
}
