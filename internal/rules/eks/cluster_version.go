package eks

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&ClusterVersion{})
}

type ClusterVersion struct{}

func (r *ClusterVersion) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "EKS-007",
		Name:          "EKS Cluster Version Pinned",
		Description:   "EKS clusters should have an explicit Kubernetes version set.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarOperationalExcellence,
		ResourceTypes: []string{"aws_eks_cluster"},
	}
}

func (r *ClusterVersion) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetStringAttr("version"); ok && v != "" {
		return nil
	}
	return []model.Finding{{
		RuleID:      "EKS-007",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityLow,
		Pillar:      model.PillarOperationalExcellence,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "EKS cluster does not have an explicit Kubernetes version set",
		Remediation: "Set version to a specific Kubernetes version for predictable upgrades",
	}}
}
