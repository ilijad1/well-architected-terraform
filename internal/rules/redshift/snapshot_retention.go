package redshift

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&SnapshotRetention{})
}

type SnapshotRetention struct{}

func (r *SnapshotRetention) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "RS-008", Name: "Redshift Automated Snapshot Retention", Description: "Redshift clusters should have automated snapshot retention of at least 7 days.", Severity: model.SeverityMedium, Pillar: model.PillarReliability, ResourceTypes: []string{"aws_redshift_cluster"}}
}

func (r *SnapshotRetention) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetNumberAttr("automated_snapshot_retention_period"); ok && v >= 7 {
		return nil
	}
	return []model.Finding{{RuleID: "RS-008", RuleName: r.Metadata().Name, Severity: model.SeverityMedium, Pillar: model.PillarReliability, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "Redshift cluster automated snapshot retention is less than 7 days.", Remediation: "Set automated_snapshot_retention_period >= 7."}}
}
