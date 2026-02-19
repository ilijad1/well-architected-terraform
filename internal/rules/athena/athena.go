// Package athena contains Well-Architected rules for AWS ATHENA resources.
package athena

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&ResultEncryption{})
	engine.Register(&EnforceConfig{})
}

type ResultEncryption struct{}

func (r *ResultEncryption) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "ATH-001", Name: "Athena Workgroup Result Encryption", Description: "Athena workgroups should encrypt query results.", Severity: model.SeverityHigh, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_athena_workgroup"}}
}

func (r *ResultEncryption) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, cfg := range resource.GetBlocks("configuration") {
		for _, rc := range cfg.Blocks["result_configuration"] {
			if len(rc.Blocks["encryption_configuration"]) > 0 {
				return nil
			}
		}
	}
	return []model.Finding{{RuleID: "ATH-001", RuleName: r.Metadata().Name, Severity: model.SeverityHigh, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "Athena workgroup does not encrypt query results.", Remediation: "Add configuration.result_configuration.encryption_configuration block."}}
}

type EnforceConfig struct{}

func (r *EnforceConfig) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "ATH-002", Name: "Athena Enforce Workgroup Configuration", Description: "Athena workgroups should enforce workgroup configuration.", Severity: model.SeverityMedium, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_athena_workgroup"}}
}

func (r *EnforceConfig) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, cfg := range resource.GetBlocks("configuration") {
		if v, ok := cfg.GetBoolAttr("enforce_workgroup_configuration"); ok && v {
			return nil
		}
	}
	return []model.Finding{{RuleID: "ATH-002", RuleName: r.Metadata().Name, Severity: model.SeverityMedium, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "Athena workgroup does not enforce workgroup configuration.", Remediation: "Set configuration.enforce_workgroup_configuration = true."}}
}
