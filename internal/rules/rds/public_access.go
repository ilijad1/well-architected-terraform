package rds

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&PublicAccess{})
}

// PublicAccess checks that RDS instances are not publicly accessible.
type PublicAccess struct{}

func (r *PublicAccess) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "RDS-002",
		Name:          "RDS Public Access",
		Description:   "RDS instances should not be publicly accessible.",
		Severity:      model.SeverityCritical,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_db_instance"},
		DocURL:        "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html",
	}
}

func (r *PublicAccess) Evaluate(resource model.TerraformResource) []model.Finding {
	publiclyAccessible, ok := resource.GetBoolAttr("publicly_accessible")
	if !ok || !publiclyAccessible {
		return nil
	}

	return []model.Finding{{
		RuleID:      "RDS-002",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityCritical,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "RDS instance is publicly accessible. This exposes the database to the internet.",
		Remediation: "Set publicly_accessible = false and access the database through a VPC.",
		DocURL:      r.Metadata().DocURL,
	}}
}
