// Package rds contains Well-Architected rules for AWS RDS resources.
package rds

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&AutoMinorVersion{})
}

type AutoMinorVersion struct{}

func (r *AutoMinorVersion) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "RDS-008",
		Name:          "RDS Auto Minor Version Upgrade",
		Description:   "RDS instances should have auto minor version upgrade enabled.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarOperationalExcellence,
		ResourceTypes: []string{"aws_db_instance"},
	}
}

func (r *AutoMinorVersion) Evaluate(resource model.TerraformResource) []model.Finding {
	autoUpgrade, ok := resource.GetBoolAttr("auto_minor_version_upgrade")
	if ok && !autoUpgrade {
		return []model.Finding{{
			RuleID:      "RDS-008",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarOperationalExcellence,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "RDS instance has auto minor version upgrade explicitly disabled.",
			Remediation: "Set auto_minor_version_upgrade = true or remove the attribute (defaults to true).",
		}}
	}

	return nil
}
