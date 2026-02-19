package ec2

import (
	"fmt"
	"strings"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&InstanceGeneration{})
}

// InstanceGeneration checks that EC2 instances use current-generation instance types.
type InstanceGeneration struct{}

func (r *InstanceGeneration) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "EC2-005",
		Name:          "EC2 Current Generation Instance Type",
		Description:   "EC2 instances should use current-generation instance types for better price/performance.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarPerformanceEfficiency,
		ResourceTypes: []string{"aws_instance"},
	}
}

// previousGenPrefixes are instance type family prefixes for previous-generation types.
var previousGenPrefixes = []string{
	"t1.", "t2.", "m1.", "m2.", "m3.", "m4.",
	"c1.", "c3.", "c4.",
	"r3.", "r4.",
	"i2.", "i3.",
	"d2.",
	"g2.",
	"p2.",
	"x1.",
}

func (r *InstanceGeneration) Evaluate(resource model.TerraformResource) []model.Finding {
	instanceType, ok := resource.GetStringAttr("instance_type")
	if !ok {
		return nil
	}

	for _, prefix := range previousGenPrefixes {
		if strings.HasPrefix(instanceType, prefix) {
			return []model.Finding{{
				RuleID:      "EC2-005",
				RuleName:    r.Metadata().Name,
				Severity:    model.SeverityLow,
				Pillar:      model.PillarPerformanceEfficiency,
				Resource:    resource.Address(),
				File:        resource.File,
				Line:        resource.Line,
				Description: fmt.Sprintf("EC2 instance uses previous-generation instance type '%s'.", instanceType),
				Remediation: "Consider upgrading to a current-generation instance type (e.g., t3, m5, c5, r5) for better price/performance.",
			}}
		}
	}

	return nil
}
