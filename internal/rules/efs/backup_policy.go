package efs

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&BackupPolicy{})
}

type BackupPolicy struct{}

func (r *BackupPolicy) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "EFS-002",
		Name:          "EFS Backup Policy Enabled",
		Description:   "EFS file systems should have automatic backups enabled.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarReliability,
		ResourceTypes: []string{"aws_efs_backup_policy"},
	}
}

func (r *BackupPolicy) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, block := range resource.GetBlocks("backup_policy") {
		status, ok := block.GetStringAttr("status")
		if ok && status == "ENABLED" {
			return nil
		}
	}

	return []model.Finding{{
		RuleID:      "EFS-002",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarReliability,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "EFS backup policy is not enabled.",
		Remediation: "Add backup_policy block with status = \"ENABLED\".",
	}}
}
