// Package sustainability contains Well-Architected rules for AWS SUSTAINABILITY resources.
package sustainability

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// ASGMixedInstancesRule checks that Auto Scaling Groups use mixed instances policies for Spot capacity.
type ASGMixedInstancesRule struct{}

func init() {
	engine.Register(&ASGMixedInstancesRule{})
}

func (r *ASGMixedInstancesRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "SUS-006",
		Name:          "ASG Missing Mixed Instances Policy",
		Description:   "Auto Scaling Groups should use mixed instances policies to leverage Spot instances, reducing resource waste.",
		Severity:      model.SeverityInfo,
		Pillar:        model.PillarSustainability,
		ResourceTypes: []string{"aws_autoscaling_group"},
	}
}

func (r *ASGMixedInstancesRule) Evaluate(resource model.TerraformResource) []model.Finding {
	if resource.HasBlock("mixed_instances_policy") {
		return nil
	}

	return []model.Finding{{
		RuleID:      "SUS-006",
		RuleName:    "ASG Missing Mixed Instances Policy",
		Severity:    model.SeverityInfo,
		Pillar:      model.PillarSustainability,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "This Auto Scaling Group does not use a mixed instances policy. Mixed instance policies allow using Spot instances alongside On-Demand, improving resource utilization and reducing waste.",
		Remediation: "Add a mixed_instances_policy block with an instances_distribution that includes spot_allocation_strategy and spot_instance_pools.",
	}}
}
