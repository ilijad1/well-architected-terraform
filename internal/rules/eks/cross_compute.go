package eks

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// CrossComputeRule checks that every EKS cluster has at least one node group
// or Fargate profile defined in the plan.
type CrossComputeRule struct{}

func init() {
	engine.RegisterCross(&CrossComputeRule{})
}

func (r *CrossComputeRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "EKS-009",
		Name:          "EKS Cluster Missing Compute (Node Group or Fargate Profile)",
		Description:   "Every EKS cluster should have at least one aws_eks_node_group or aws_eks_fargate_profile to ensure workloads have compute capacity.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarReliability,
		ResourceTypes: []string{"aws_eks_cluster", "aws_eks_node_group", "aws_eks_fargate_profile"},
	}
}

func (r *CrossComputeRule) EvaluateAll(resources []model.TerraformResource) []model.Finding {
	// Collect all cluster names referenced by node groups and Fargate profiles
	clustersWithCompute := make(map[string]bool)
	for _, res := range resources {
		if res.Type == "aws_eks_node_group" || res.Type == "aws_eks_fargate_profile" {
			clusterName, ok := res.GetStringAttr("cluster_name")
			if ok && clusterName != "" {
				clustersWithCompute[clusterName] = true
			}
			// Also index by resource name as fallback for reference-based values
			clustersWithCompute[res.Name] = true
		}
	}

	var findings []model.Finding
	for _, res := range resources {
		if res.Type != "aws_eks_cluster" {
			continue
		}

		clusterName, _ := res.GetStringAttr("name")

		if !clustersWithCompute[clusterName] && !clustersWithCompute[res.Name] && !clustersWithCompute[res.Address()] {
			findings = append(findings, model.Finding{
				RuleID:      "EKS-009",
				RuleName:    "EKS Cluster Missing Compute (Node Group or Fargate Profile)",
				Severity:    model.SeverityHigh,
				Pillar:      model.PillarReliability,
				Resource:    res.Address(),
				File:        res.File,
				Line:        res.Line,
				Description: "This EKS cluster has no aws_eks_node_group or aws_eks_fargate_profile in the plan. Without compute resources, workloads cannot be scheduled.",
				Remediation: "Add an aws_eks_node_group or aws_eks_fargate_profile that references this cluster via cluster_name.",
			})
		}
	}

	return findings
}
