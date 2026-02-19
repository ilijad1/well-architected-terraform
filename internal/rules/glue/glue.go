package glue

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&SecurityConfigEncryption{})
	engine.Register(&CatalogEncryption{})
	engine.Register(&ConnectionPasswordEncryption{})
}

type SecurityConfigEncryption struct{}

func (r *SecurityConfigEncryption) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "GLU-001", Name: "Glue Security Configuration Encryption", Description: "Glue security configurations should have encryption configured.", Severity: model.SeverityHigh, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_glue_security_configuration"}}
}

func (r *SecurityConfigEncryption) Evaluate(resource model.TerraformResource) []model.Finding {
	if len(resource.GetBlocks("encryption_configuration")) > 0 {
		return nil
	}
	return []model.Finding{{RuleID: "GLU-001", RuleName: r.Metadata().Name, Severity: model.SeverityHigh, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "Glue security configuration does not have encryption configured.", Remediation: "Add encryption_configuration block."}}
}

type CatalogEncryption struct{}

func (r *CatalogEncryption) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "GLU-002", Name: "Glue Data Catalog Encryption at Rest", Description: "Glue data catalog should use SSE-KMS encryption at rest.", Severity: model.SeverityHigh, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_glue_data_catalog_encryption_settings"}}
}

func (r *CatalogEncryption) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, dces := range resource.GetBlocks("data_catalog_encryption_settings") {
		for _, ear := range dces.Blocks["encryption_at_rest"] {
			if v, ok := ear.GetStringAttr("catalog_encryption_mode"); ok && v == "SSE-KMS" {
				return nil
			}
		}
	}
	return []model.Finding{{RuleID: "GLU-002", RuleName: r.Metadata().Name, Severity: model.SeverityHigh, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "Glue data catalog does not use SSE-KMS encryption at rest.", Remediation: "Set data_catalog_encryption_settings.encryption_at_rest.catalog_encryption_mode = \"SSE-KMS\"."}}
}

type ConnectionPasswordEncryption struct{}

func (r *ConnectionPasswordEncryption) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "GLU-003", Name: "Glue Connection Password Encryption", Description: "Glue data catalog should encrypt connection passwords.", Severity: model.SeverityHigh, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_glue_data_catalog_encryption_settings"}}
}

func (r *ConnectionPasswordEncryption) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, dces := range resource.GetBlocks("data_catalog_encryption_settings") {
		for _, cpe := range dces.Blocks["connection_password_encryption"] {
			if v, ok := cpe.GetBoolAttr("return_connection_password_encrypted"); ok && v {
				return nil
			}
		}
	}
	return []model.Finding{{RuleID: "GLU-003", RuleName: r.Metadata().Name, Severity: model.SeverityHigh, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "Glue data catalog does not encrypt connection passwords.", Remediation: "Set data_catalog_encryption_settings.connection_password_encryption.return_connection_password_encrypted = true."}}
}
