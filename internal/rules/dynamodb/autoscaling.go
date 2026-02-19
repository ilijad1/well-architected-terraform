package dynamodb

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&Autoscaling{})
}

type Autoscaling struct{}

func (r *Autoscaling) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "DDB-005",
		Name:          "DynamoDB Autoscaling Target",
		Description:   "DynamoDB autoscaling targets should have min and max capacity configured.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarPerformanceEfficiency,
		ResourceTypes: []string{"aws_appautoscaling_target"},
	}
}

func (r *Autoscaling) Evaluate(resource model.TerraformResource) []model.Finding {
	ns, ok := resource.GetStringAttr("service_namespace")
	if !ok || ns != "dynamodb" {
		return nil
	}
	minCap, hasMin := resource.GetNumberAttr("min_capacity")
	maxCap, hasMax := resource.GetNumberAttr("max_capacity")
	if hasMin && hasMax && minCap > 0 && maxCap > 0 {
		return nil
	}
	return []model.Finding{{
		RuleID:      "DDB-005",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityLow,
		Pillar:      model.PillarPerformanceEfficiency,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "DynamoDB autoscaling target does not have min and max capacity properly configured",
		Remediation: "Set min_capacity and max_capacity to positive values",
	}}
}
