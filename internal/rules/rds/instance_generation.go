package rds

import (
	"fmt"
	"strings"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&InstanceGeneration{})
}

// InstanceGeneration checks that RDS instances use current-generation instance classes.
type InstanceGeneration struct{}

func (r *InstanceGeneration) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "RDS-005",
		Name:          "RDS Current Generation Instance Class",
		Description:   "RDS instances should use current-generation instance classes for better price/performance.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarPerformanceEfficiency,
		ResourceTypes: []string{"aws_db_instance"},
	}
}

var previousGenDBPrefixes = []string{
	"db.t2.", "db.t1.",
	"db.m1.", "db.m2.", "db.m3.", "db.m4.",
	"db.r3.", "db.r4.",
	"db.cr1.",
}

func (r *InstanceGeneration) Evaluate(resource model.TerraformResource) []model.Finding {
	instanceClass, ok := resource.GetStringAttr("instance_class")
	if !ok {
		return nil
	}

	for _, prefix := range previousGenDBPrefixes {
		if strings.HasPrefix(instanceClass, prefix) {
			return []model.Finding{{
				RuleID:      "RDS-005",
				RuleName:    r.Metadata().Name,
				Severity:    model.SeverityLow,
				Pillar:      model.PillarPerformanceEfficiency,
				Resource:    resource.Address(),
				File:        resource.File,
				Line:        resource.Line,
				Description: fmt.Sprintf("RDS instance uses previous-generation instance class '%s'.", instanceClass),
				Remediation: "Consider upgrading to a current-generation instance class (e.g., db.t3, db.m5, db.r5, db.m6g).",
			}}
		}
	}

	return nil
}
