package rds

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&StorageEncryption{})
}

// StorageEncryption checks that RDS instances have storage encryption enabled.
type StorageEncryption struct{}

func (r *StorageEncryption) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "RDS-001",
		Name:          "RDS Storage Encryption",
		Description:   "RDS instances should have storage encryption enabled to protect data at rest.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_db_instance"},
		DocURL:        "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
	}
}

func (r *StorageEncryption) Evaluate(resource model.TerraformResource) []model.Finding {
	encrypted, ok := resource.GetBoolAttr("storage_encrypted")
	if ok && encrypted {
		return nil
	}

	return []model.Finding{{
		RuleID:      "RDS-001",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityHigh,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "RDS instance does not have storage encryption enabled.",
		Remediation: "Set storage_encrypted = true. Note: encryption can only be enabled at creation time.",
		DocURL:      r.Metadata().DocURL,
	}}
}
