package rds

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&MultiAZ{})
}

// MultiAZ checks that RDS instances have Multi-AZ deployment enabled.
type MultiAZ struct{}

func (r *MultiAZ) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "RDS-003",
		Name:          "RDS Multi-AZ Deployment",
		Description:   "RDS instances should have Multi-AZ enabled for high availability.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarReliability,
		ResourceTypes: []string{"aws_db_instance"},
	}
}

func (r *MultiAZ) Evaluate(resource model.TerraformResource) []model.Finding {
	multiAZ, ok := resource.GetBoolAttr("multi_az")
	if ok && multiAZ {
		return nil
	}

	return []model.Finding{{
		RuleID:      "RDS-003",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarReliability,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "RDS instance does not have Multi-AZ deployment enabled.",
		Remediation: "Set multi_az = true to enable automatic failover to a standby instance.",
	}}
}
