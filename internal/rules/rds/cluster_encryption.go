package rds

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&ClusterEncryption{})
}

type ClusterEncryption struct{}

func (r *ClusterEncryption) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "RDS-010",
		Name:          "RDS Cluster Storage Encryption",
		Description:   "RDS Aurora clusters should have storage encryption enabled.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_rds_cluster"},
	}
}

func (r *ClusterEncryption) Evaluate(resource model.TerraformResource) []model.Finding {
	encrypted, ok := resource.GetBoolAttr("storage_encrypted")
	if ok && encrypted {
		return nil
	}

	return []model.Finding{{
		RuleID:      "RDS-010",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityHigh,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "RDS cluster does not have storage encryption enabled.",
		Remediation: "Set storage_encrypted = true on the RDS cluster.",
	}}
}
