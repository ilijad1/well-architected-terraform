package rds

import (
	"fmt"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&BackupRetentionMin{})
}

type BackupRetentionMin struct{}

func (r *BackupRetentionMin) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "RDS-009",
		Name:          "RDS Backup Retention Minimum 7 Days",
		Description:   "RDS instances should have backup retention period of at least 7 days.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarReliability,
		ResourceTypes: []string{"aws_db_instance"},
	}
}

func (r *BackupRetentionMin) Evaluate(resource model.TerraformResource) []model.Finding {
	retention, ok := resource.GetNumberAttr("backup_retention_period")
	if !ok {
		return nil
	}
	if retention >= 7 {
		return nil
	}

	return []model.Finding{{
		RuleID:      "RDS-009",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarReliability,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: fmt.Sprintf("RDS instance backup retention period is %.0f days, should be at least 7.", retention),
		Remediation: "Set backup_retention_period to at least 7 days.",
	}}
}
