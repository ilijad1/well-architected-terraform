package sustainability

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// RDSStorageAutoscalingRule checks if RDS instances have storage autoscaling enabled.
type RDSStorageAutoscalingRule struct{}

func init() {
	engine.Register(&RDSStorageAutoscalingRule{})
}

func (r *RDSStorageAutoscalingRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "SUS-008",
		Name:          "RDS Missing Storage Autoscaling",
		Description:   "RDS instances should have max_allocated_storage set to enable storage autoscaling and avoid over-provisioning.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarSustainability,
		ResourceTypes: []string{"aws_db_instance"},
	}
}

func (r *RDSStorageAutoscalingRule) Evaluate(resource model.TerraformResource) []model.Finding {
	_, ok := resource.GetNumberAttr("max_allocated_storage")
	if ok {
		return nil
	}

	return []model.Finding{{
		RuleID:      "SUS-008",
		RuleName:    "RDS Missing Storage Autoscaling",
		Severity:    model.SeverityLow,
		Pillar:      model.PillarSustainability,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "This RDS instance has no max_allocated_storage configured, meaning storage autoscaling is disabled. This often leads to over-provisioning of storage.",
		Remediation: "Set max_allocated_storage to enable storage autoscaling. This allows storage to scale up only when needed, reducing waste.",
	}}
}
