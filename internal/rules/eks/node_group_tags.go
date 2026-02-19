package eks

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&NodeGroupTags{})
}

type NodeGroupTags struct{}

func (r *NodeGroupTags) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "EKS-005",
		Name:          "EKS Node Group Tags",
		Description:   "Ensures EKS node groups have tags for cost tracking and resource management",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarCostOptimization,
		ResourceTypes: []string{"aws_eks_node_group"},
		DocURL:        "https://docs.aws.amazon.com/eks/latest/userguide/eks-using-tags.html",
	}
}

func (r *NodeGroupTags) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	tags, ok := resource.Attributes["tags"].(map[string]interface{})
	if !ok || len(tags) == 0 {
		findings = append(findings, model.Finding{
			RuleID:      "EKS-005",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityLow,
			Pillar:      model.PillarCostOptimization,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "EKS node group does not have tags configured",
			Remediation: "Add tags to the node group for cost allocation, resource management, and organizational purposes (e.g., Environment, Owner, CostCenter)",
			DocURL:      r.Metadata().DocURL,
		})
	}

	return findings
}
