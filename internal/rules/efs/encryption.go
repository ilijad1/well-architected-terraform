package efs

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&Encryption{})
}

type Encryption struct{}

func (r *Encryption) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "EFS-001",
		Name:          "EFS Encryption at Rest",
		Description:   "EFS file systems should have encryption at rest enabled.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_efs_file_system"},
	}
}

func (r *Encryption) Evaluate(resource model.TerraformResource) []model.Finding {
	encrypted, ok := resource.GetBoolAttr("encrypted")
	if ok && encrypted {
		return nil
	}

	return []model.Finding{{
		RuleID:      "EFS-001",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityHigh,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "EFS file system does not have encryption at rest enabled.",
		Remediation: "Set encrypted = true on the EFS file system.",
	}}
}
