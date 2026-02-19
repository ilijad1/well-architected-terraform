package efs

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&Tags{})
}

type Tags struct{}

func (r *Tags) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "EFS-003",
		Name:          "EFS File System Tags",
		Description:   "EFS file systems should have tags for cost allocation and organization.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarCostOptimization,
		ResourceTypes: []string{"aws_efs_file_system"},
	}
}

func (r *Tags) Evaluate(resource model.TerraformResource) []model.Finding {
	if _, ok := resource.Attributes["tags"]; ok {
		return nil
	}

	return []model.Finding{{
		RuleID:      "EFS-003",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityLow,
		Pillar:      model.PillarCostOptimization,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "EFS file system does not have tags configured.",
		Remediation: "Add tags for cost allocation and resource organization.",
	}}
}
