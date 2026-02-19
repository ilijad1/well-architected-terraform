package ec2

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&DetailedMonitoring{})
}

// DetailedMonitoring checks that EC2 instances have detailed monitoring enabled.
type DetailedMonitoring struct{}

func (r *DetailedMonitoring) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "EC2-004",
		Name:          "EC2 Detailed Monitoring",
		Description:   "EC2 instances should have detailed monitoring enabled for better observability.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarOperationalExcellence,
		ResourceTypes: []string{"aws_instance"},
	}
}

func (r *DetailedMonitoring) Evaluate(resource model.TerraformResource) []model.Finding {
	monitoring, ok := resource.GetBoolAttr("monitoring")
	if ok && monitoring {
		return nil
	}

	return []model.Finding{{
		RuleID:      "EC2-004",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityLow,
		Pillar:      model.PillarOperationalExcellence,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "EC2 instance does not have detailed monitoring enabled (1-minute intervals).",
		Remediation: "Set monitoring = true to enable detailed CloudWatch monitoring.",
	}}
}
