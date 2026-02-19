package waf

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&LoggingConfig{})
	engine.Register(&RulesPresent{})
	engine.Register(&DefaultBlock{})
}

type LoggingConfig struct{}

func (r *LoggingConfig) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "WAF-001", Name: "WAF Logging Configuration", Description: "WAFv2 web ACLs should have logging configured.", Severity: model.SeverityMedium, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_wafv2_web_acl_logging_configuration"}}
}

func (r *LoggingConfig) Evaluate(resource model.TerraformResource) []model.Finding {
	arn, hasArn := resource.GetStringAttr("resource_arn")
	if hasArn && arn != "" {
		if _, ok := resource.Attributes["log_destination_configs"]; ok {
			return nil
		}
	}
	return []model.Finding{{RuleID: "WAF-001", RuleName: r.Metadata().Name, Severity: model.SeverityMedium, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "WAF logging configuration is incomplete.", Remediation: "Set resource_arn and log_destination_configs."}}
}

type RulesPresent struct{}

func (r *RulesPresent) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "WAF-002", Name: "WAF Rules Present", Description: "WAFv2 web ACLs should have at least one rule.", Severity: model.SeverityHigh, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_wafv2_web_acl"}}
}

func (r *RulesPresent) Evaluate(resource model.TerraformResource) []model.Finding {
	if resource.HasBlock("rule") {
		return nil
	}
	return []model.Finding{{RuleID: "WAF-002", RuleName: r.Metadata().Name, Severity: model.SeverityHigh, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "WAF web ACL does not have any rules configured.", Remediation: "Add at least one rule block to the web ACL."}}
}

type DefaultBlock struct{}

func (r *DefaultBlock) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "WAF-003", Name: "WAF Default Action Block", Description: "WAFv2 web ACLs should have default action set to block.", Severity: model.SeverityMedium, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_wafv2_web_acl"}}
}

func (r *DefaultBlock) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, da := range resource.GetBlocks("default_action") {
		if _, ok := da.Blocks["block"]; ok {
			return nil
		}
	}
	return []model.Finding{{RuleID: "WAF-003", RuleName: r.Metadata().Name, Severity: model.SeverityMedium, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "WAF web ACL default action is not set to block.", Remediation: "Set default_action to block{}."}}
}
