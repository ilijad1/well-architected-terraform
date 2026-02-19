package eks

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&NodeGroupInstanceTypes{})
}

type NodeGroupInstanceTypes struct{}

func (r *NodeGroupInstanceTypes) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "EKS-006",
		Name:          "EKS Node Group Instance Types",
		Description:   "EKS node groups should explicitly set instance types for cost optimization.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarCostOptimization,
		ResourceTypes: []string{"aws_eks_node_group"},
	}
}

func (r *NodeGroupInstanceTypes) Evaluate(resource model.TerraformResource) []model.Finding {
	if types, ok := resource.Attributes["instance_types"]; ok {
		if list, ok := types.([]interface{}); ok && len(list) > 0 {
			return nil
		}
	}
	return []model.Finding{{
		RuleID:      "EKS-006",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityLow,
		Pillar:      model.PillarCostOptimization,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "EKS node group does not explicitly set instance types",
		Remediation: "Set instance_types to control cost and performance characteristics",
	}}
}
