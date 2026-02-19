package sustainability

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// GravitonEKSRule checks if EKS node groups use Graviton (ARM) instance types.
type GravitonEKSRule struct{}

func init() {
	engine.Register(&GravitonEKSRule{})
}

func (r *GravitonEKSRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "SUS-009",
		Name:          "EKS Node Group Not Using Graviton",
		Description:   "EKS node groups should use Graviton (ARM) instance types for better energy efficiency and price-performance.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarSustainability,
		ResourceTypes: []string{"aws_eks_node_group"},
	}
}

func (r *GravitonEKSRule) Evaluate(resource model.TerraformResource) []model.Finding {
	types, ok := resource.Attributes["instance_types"]
	if !ok || types == nil {
		return nil
	}

	typeList, ok := types.([]interface{})
	if !ok || len(typeList) == 0 {
		return nil
	}

	for _, t := range typeList {
		if s, ok := t.(string); ok && isGravitonInstanceType(s) {
			return nil
		}
	}

	return []model.Finding{{
		RuleID:      "SUS-009",
		RuleName:    "EKS Node Group Not Using Graviton",
		Severity:    model.SeverityLow,
		Pillar:      model.PillarSustainability,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "None of the instance types in this EKS node group use Graviton processors. Graviton instances offer better price-performance and lower energy consumption.",
		Remediation: "Consider using Graviton instance types such as m7g, c7g, r7g, or t4g. Ensure your container images are built for ARM64.",
	}}
}
