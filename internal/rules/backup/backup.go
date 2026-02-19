package backup

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&VaultEncryption{})
	engine.Register(&PlanLifecycle{})
}

type VaultEncryption struct{}

func (r *VaultEncryption) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "BKP-001", Name: "Backup Vault KMS Encryption", Description: "Backup vaults should use a customer-managed KMS key.", Severity: model.SeverityMedium, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_backup_vault"}}
}

func (r *VaultEncryption) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetStringAttr("kms_key_arn"); ok && v != "" {
		return nil
	}
	return []model.Finding{{RuleID: "BKP-001", RuleName: r.Metadata().Name, Severity: model.SeverityMedium, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "Backup vault does not use a customer-managed KMS key.", Remediation: "Set kms_key_arn to a KMS key ARN."}}
}

type PlanLifecycle struct{}

func (r *PlanLifecycle) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "BKP-002", Name: "Backup Plan Lifecycle", Description: "Backup plan rules should have a lifecycle configuration.", Severity: model.SeverityLow, Pillar: model.PillarReliability, ResourceTypes: []string{"aws_backup_plan"}}
}

func (r *PlanLifecycle) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, rule := range resource.GetBlocks("rule") {
		if len(rule.Blocks["lifecycle"]) > 0 {
			return nil
		}
	}
	return []model.Finding{{RuleID: "BKP-002", RuleName: r.Metadata().Name, Severity: model.SeverityLow, Pillar: model.PillarReliability, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "Backup plan rule does not have a lifecycle configuration.", Remediation: "Add lifecycle block to backup plan rules."}}
}
