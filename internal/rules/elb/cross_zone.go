package elb

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&CrossZoneRule{})
}

type CrossZoneRule struct{}

func (r *CrossZoneRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "ELB-006",
		Name:          "ELB Cross-Zone Load Balancing",
		Description:   "Load balancers should have cross-zone load balancing enabled.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarReliability,
		ResourceTypes: []string{"aws_lb"},
	}
}

func (r *CrossZoneRule) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetBoolAttr("enable_cross_zone_load_balancing"); ok && v {
		return nil
	}
	return []model.Finding{{
		RuleID:      "ELB-006",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarReliability,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "Load balancer does not have cross-zone load balancing enabled",
		Remediation: "Set enable_cross_zone_load_balancing = true",
	}}
}
