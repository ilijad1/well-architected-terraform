// Package dms contains rules for AWS Database Migration Service resources.
package dms

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&NotPublic{})
	engine.Register(&KMSEncryption{})
	engine.Register(&AutoMinorVersion{})
}

type NotPublic struct{}

func (r *NotPublic) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "DMS-001", Name: "DMS Replication Instance Not Public", Description: "DMS replication instances should not be publicly accessible.", Severity: model.SeverityCritical, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_dms_replication_instance"}}
}

func (r *NotPublic) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetBoolAttr("publicly_accessible"); ok && !v {
		return nil
	}
	return []model.Finding{{RuleID: "DMS-001", RuleName: r.Metadata().Name, Severity: model.SeverityCritical, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "DMS replication instance is publicly accessible.", Remediation: "Set publicly_accessible = false."}}
}

type KMSEncryption struct{}

func (r *KMSEncryption) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "DMS-002", Name: "DMS Replication Instance KMS Encryption", Description: "DMS replication instances should use a KMS key.", Severity: model.SeverityMedium, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_dms_replication_instance"}}
}

func (r *KMSEncryption) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetStringAttr("kms_key_arn"); ok && v != "" {
		return nil
	}
	return []model.Finding{{RuleID: "DMS-002", RuleName: r.Metadata().Name, Severity: model.SeverityMedium, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "DMS replication instance does not use a KMS key.", Remediation: "Set kms_key_arn to a KMS key ARN."}}
}

type AutoMinorVersion struct{}

func (r *AutoMinorVersion) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "DMS-003", Name: "DMS Auto Minor Version Upgrade", Description: "DMS replication instances should have auto minor version upgrade enabled.", Severity: model.SeverityLow, Pillar: model.PillarOperationalExcellence, ResourceTypes: []string{"aws_dms_replication_instance"}}
}

func (r *AutoMinorVersion) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetBoolAttr("auto_minor_version_upgrade"); ok && !v {
		return []model.Finding{{RuleID: "DMS-003", RuleName: r.Metadata().Name, Severity: model.SeverityLow, Pillar: model.PillarOperationalExcellence, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "DMS replication instance does not have auto minor version upgrade enabled.", Remediation: "Set auto_minor_version_upgrade = true or remove the attribute (defaults to true)."}}
	}
	return nil
}
