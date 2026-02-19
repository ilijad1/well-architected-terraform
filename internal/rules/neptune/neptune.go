package neptune

import (
	"fmt"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&Encryption{})
	engine.Register(&AuditLogs{})
	engine.Register(&DeletionProtection{})
	engine.Register(&IAMAuth{})
	engine.Register(&BackupRetention{})
	engine.Register(&CopyTagsToSnapshot{})
}

type Encryption struct{}

func (r *Encryption) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "NEP-001", Name: "Neptune Encryption", Description: "Neptune clusters should have storage encryption enabled.", Severity: model.SeverityHigh, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_neptune_cluster"}}
}

func (r *Encryption) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetBoolAttr("storage_encrypted"); ok && v {
		return nil
	}
	return []model.Finding{{RuleID: "NEP-001", RuleName: r.Metadata().Name, Severity: model.SeverityHigh, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "Neptune cluster does not have storage encryption enabled.", Remediation: "Set storage_encrypted = true."}}
}

type AuditLogs struct{}

func (r *AuditLogs) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "NEP-002", Name: "Neptune Audit Logs", Description: "Neptune clusters should export audit logs.", Severity: model.SeverityMedium, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_neptune_cluster"}}
}

func (r *AuditLogs) Evaluate(resource model.TerraformResource) []model.Finding {
	if exports, ok := resource.Attributes["enable_cloudwatch_logs_exports"]; ok {
		if list, ok := exports.([]interface{}); ok {
			for _, item := range list {
				if s, ok := item.(string); ok && s == "audit" {
					return nil
				}
			}
		}
	}
	return []model.Finding{{RuleID: "NEP-002", RuleName: r.Metadata().Name, Severity: model.SeverityMedium, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "Neptune cluster does not export audit logs.", Remediation: "Add \"audit\" to enable_cloudwatch_logs_exports."}}
}

type DeletionProtection struct{}

func (r *DeletionProtection) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "NEP-003", Name: "Neptune Deletion Protection", Description: "Neptune clusters should have deletion protection enabled.", Severity: model.SeverityMedium, Pillar: model.PillarReliability, ResourceTypes: []string{"aws_neptune_cluster"}}
}

func (r *DeletionProtection) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetBoolAttr("deletion_protection"); ok && v {
		return nil
	}
	return []model.Finding{{RuleID: "NEP-003", RuleName: r.Metadata().Name, Severity: model.SeverityMedium, Pillar: model.PillarReliability, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "Neptune cluster does not have deletion protection enabled.", Remediation: "Set deletion_protection = true."}}
}

type IAMAuth struct{}

func (r *IAMAuth) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "NEP-004", Name: "Neptune IAM Authentication", Description: "Neptune clusters should have IAM database authentication enabled.", Severity: model.SeverityMedium, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_neptune_cluster"}}
}

func (r *IAMAuth) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetBoolAttr("iam_database_authentication_enabled"); ok && v {
		return nil
	}
	return []model.Finding{{RuleID: "NEP-004", RuleName: r.Metadata().Name, Severity: model.SeverityMedium, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "Neptune cluster does not have IAM authentication enabled.", Remediation: "Set iam_database_authentication_enabled = true."}}
}

type BackupRetention struct{}

func (r *BackupRetention) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "NEP-005", Name: "Neptune Backup Retention", Description: "Neptune clusters should have backup retention of at least 7 days.", Severity: model.SeverityMedium, Pillar: model.PillarReliability, ResourceTypes: []string{"aws_neptune_cluster"}}
}

func (r *BackupRetention) Evaluate(resource model.TerraformResource) []model.Finding {
	retention, ok := resource.GetNumberAttr("backup_retention_period")
	if ok && retention >= 7 {
		return nil
	}
	return []model.Finding{{RuleID: "NEP-005", RuleName: r.Metadata().Name, Severity: model.SeverityMedium, Pillar: model.PillarReliability, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: fmt.Sprintf("Neptune cluster backup retention is %.0f days, should be at least 7.", retention), Remediation: "Set backup_retention_period to at least 7."}}
}

type CopyTagsToSnapshot struct{}

func (r *CopyTagsToSnapshot) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "NEP-006", Name: "Neptune Copy Tags to Snapshot", Description: "Neptune clusters should copy tags to snapshots.", Severity: model.SeverityLow, Pillar: model.PillarOperationalExcellence, ResourceTypes: []string{"aws_neptune_cluster"}}
}

func (r *CopyTagsToSnapshot) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetBoolAttr("copy_tags_to_snapshot"); ok && v {
		return nil
	}
	return []model.Finding{{RuleID: "NEP-006", RuleName: r.Metadata().Name, Severity: model.SeverityLow, Pillar: model.PillarOperationalExcellence, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "Neptune cluster does not copy tags to snapshots.", Remediation: "Set copy_tags_to_snapshot = true."}}
}
