package rds

import (
	"fmt"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&BackupRetention{})
}

// BackupRetention checks that RDS instances have backup retention configured.
type BackupRetention struct{}

func (r *BackupRetention) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "RDS-004",
		Name:          "RDS Backup Retention",
		Description:   "RDS instances should have backup retention period greater than 0.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarReliability,
		ResourceTypes: []string{"aws_db_instance"},
		DocURL:        "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html",
	}
}

func (r *BackupRetention) Evaluate(resource model.TerraformResource) []model.Finding {
	retention, ok := resource.GetNumberAttr("backup_retention_period")
	if ok && retention > 0 {
		return nil
	}

	return []model.Finding{{
		RuleID:      "RDS-004",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityHigh,
		Pillar:      model.PillarReliability,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: fmt.Sprintf("RDS instance has backup_retention_period of %.0f days. Automated backups are effectively disabled.", retention),
		Remediation: "Set backup_retention_period to at least 7 days for production databases.",
		DocURL:      r.Metadata().DocURL,
	}}
}
