package rds

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&EnhancedMonitoring{})
}

// EnhancedMonitoring checks that RDS instances have enhanced monitoring enabled.
type EnhancedMonitoring struct{}

func (r *EnhancedMonitoring) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "RDS-011",
		Name:          "RDS Enhanced Monitoring Enabled",
		Description:   "RDS instances should have enhanced monitoring enabled to collect OS-level metrics.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarOperationalExcellence,
		ResourceTypes: []string{"aws_db_instance"},
		DocURL:        "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Monitoring.OS.html",
	}
}

func (r *EnhancedMonitoring) Evaluate(resource model.TerraformResource) []model.Finding {
	interval, ok := resource.GetNumberAttr("monitoring_interval")
	if ok && interval >= 1 {
		return nil
	}
	return []model.Finding{{
		RuleID:      "RDS-011",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarOperationalExcellence,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "RDS instance does not have enhanced monitoring enabled (monitoring_interval must be >= 1).",
		Remediation: "Set monitoring_interval to a value between 1 and 60 seconds and provide a monitoring_role_arn.",
		DocURL:      r.Metadata().DocURL,
	}}
}
