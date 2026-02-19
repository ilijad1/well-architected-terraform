// Package docdb contains Well-Architected rules for AWS DOCDB resources.
package docdb

import (
	"fmt"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&Encryption{})
	engine.Register(&AuditLogs{})
	engine.Register(&DeletionProtection{})
	engine.Register(&BackupRetention{})
	engine.Register(&TLSEnabled{})
}

type Encryption struct{}

func (r *Encryption) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "DOC-001", Name: "DocumentDB Encryption", Description: "DocumentDB clusters should have storage encryption enabled.", Severity: model.SeverityHigh, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_docdb_cluster"}}
}

func (r *Encryption) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetBoolAttr("storage_encrypted"); ok && v {
		return nil
	}
	return []model.Finding{{RuleID: "DOC-001", RuleName: r.Metadata().Name, Severity: model.SeverityHigh, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "DocumentDB cluster does not have storage encryption enabled.", Remediation: "Set storage_encrypted = true."}}
}

type AuditLogs struct{}

func (r *AuditLogs) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "DOC-002", Name: "DocumentDB Audit Logs", Description: "DocumentDB clusters should export audit logs to CloudWatch.", Severity: model.SeverityMedium, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_docdb_cluster"}}
}

func (r *AuditLogs) Evaluate(resource model.TerraformResource) []model.Finding {
	if exports, ok := resource.Attributes["enabled_cloudwatch_logs_exports"]; ok {
		if list, ok := exports.([]interface{}); ok {
			for _, item := range list {
				if s, ok := item.(string); ok && s == "audit" {
					return nil
				}
			}
		}
	}
	return []model.Finding{{RuleID: "DOC-002", RuleName: r.Metadata().Name, Severity: model.SeverityMedium, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "DocumentDB cluster does not export audit logs.", Remediation: "Add \"audit\" to enabled_cloudwatch_logs_exports."}}
}

type DeletionProtection struct{}

func (r *DeletionProtection) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "DOC-003", Name: "DocumentDB Deletion Protection", Description: "DocumentDB clusters should have deletion protection enabled.", Severity: model.SeverityMedium, Pillar: model.PillarReliability, ResourceTypes: []string{"aws_docdb_cluster"}}
}

func (r *DeletionProtection) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetBoolAttr("deletion_protection"); ok && v {
		return nil
	}
	return []model.Finding{{RuleID: "DOC-003", RuleName: r.Metadata().Name, Severity: model.SeverityMedium, Pillar: model.PillarReliability, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "DocumentDB cluster does not have deletion protection enabled.", Remediation: "Set deletion_protection = true."}}
}

type BackupRetention struct{}

func (r *BackupRetention) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "DOC-004", Name: "DocumentDB Backup Retention", Description: "DocumentDB clusters should have backup retention of at least 7 days.", Severity: model.SeverityMedium, Pillar: model.PillarReliability, ResourceTypes: []string{"aws_docdb_cluster"}}
}

func (r *BackupRetention) Evaluate(resource model.TerraformResource) []model.Finding {
	retention, ok := resource.GetNumberAttr("backup_retention_period")
	if ok && retention >= 7 {
		return nil
	}
	return []model.Finding{{RuleID: "DOC-004", RuleName: r.Metadata().Name, Severity: model.SeverityMedium, Pillar: model.PillarReliability, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: fmt.Sprintf("DocumentDB cluster backup retention is %.0f days, should be at least 7.", retention), Remediation: "Set backup_retention_period to at least 7."}}
}

type TLSEnabled struct{}

func (r *TLSEnabled) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "DOC-005", Name: "DocumentDB TLS Enabled", Description: "DocumentDB parameter groups should have TLS enabled.", Severity: model.SeverityHigh, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_docdb_cluster_parameter_group"}}
}

func (r *TLSEnabled) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, p := range resource.GetBlocks("parameter") {
		name, _ := p.GetStringAttr("name")
		value, _ := p.GetStringAttr("value")
		if name == "tls" && value == "enabled" {
			return nil
		}
	}
	return []model.Finding{{RuleID: "DOC-005", RuleName: r.Metadata().Name, Severity: model.SeverityHigh, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "DocumentDB parameter group does not have TLS enabled.", Remediation: "Add parameter with name = \"tls\" and value = \"enabled\"."}}
}
