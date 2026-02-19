package rds

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&ClusterIAMAuth{})
}

// ClusterIAMAuth checks that RDS clusters have IAM database authentication enabled.
type ClusterIAMAuth struct{}

func (r *ClusterIAMAuth) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "RDS-014",
		Name:          "RDS Cluster IAM Authentication",
		Description:   "RDS clusters should have IAM database authentication enabled to avoid storing database credentials.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_rds_cluster"},
		DocURL:        "https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/UsingWithRDS.IAMDBAuth.html",
	}
}

func (r *ClusterIAMAuth) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetBoolAttr("iam_database_authentication_enabled"); ok && v {
		return nil
	}
	return []model.Finding{{
		RuleID:      "RDS-014",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "RDS cluster does not have IAM database authentication enabled.",
		Remediation: "Set iam_database_authentication_enabled = true to use IAM roles for database access.",
		DocURL:      r.Metadata().DocURL,
	}}
}
