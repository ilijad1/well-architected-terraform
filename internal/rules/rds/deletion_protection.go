package rds

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&DeletionProtection{})
	engine.Register(&ClusterDeletionProtection{})
}

// DeletionProtection checks that RDS instances have deletion protection enabled.
type DeletionProtection struct{}

func (r *DeletionProtection) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "RDS-012",
		Name:          "RDS Instance Deletion Protection",
		Description:   "RDS instances should have deletion protection enabled to prevent accidental deletion.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarReliability,
		ResourceTypes: []string{"aws_db_instance"},
		DocURL:        "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteInstance.html",
	}
}

func (r *DeletionProtection) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetBoolAttr("deletion_protection"); ok && v {
		return nil
	}
	return []model.Finding{{
		RuleID:      "RDS-012",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityHigh,
		Pillar:      model.PillarReliability,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "RDS instance does not have deletion protection enabled.",
		Remediation: "Set deletion_protection = true to prevent accidental database deletion.",
		DocURL:      r.Metadata().DocURL,
	}}
}

// ClusterDeletionProtection checks that RDS clusters have deletion protection enabled.
type ClusterDeletionProtection struct{}

func (r *ClusterDeletionProtection) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "RDS-013",
		Name:          "RDS Cluster Deletion Protection",
		Description:   "RDS clusters should have deletion protection enabled to prevent accidental deletion.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarReliability,
		ResourceTypes: []string{"aws_rds_cluster"},
		DocURL:        "https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/USER_DeleteCluster.html",
	}
}

func (r *ClusterDeletionProtection) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetBoolAttr("deletion_protection"); ok && v {
		return nil
	}
	return []model.Finding{{
		RuleID:      "RDS-013",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityHigh,
		Pillar:      model.PillarReliability,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "RDS cluster does not have deletion protection enabled.",
		Remediation: "Set deletion_protection = true to prevent accidental cluster deletion.",
		DocURL:      r.Metadata().DocURL,
	}}
}
