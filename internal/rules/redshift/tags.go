package redshift

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&Tags{})
}

type Tags struct{}

func (r *Tags) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "RS-007", Name: "Redshift Cluster Tags", Description: "Redshift clusters should have tags for cost allocation.", Severity: model.SeverityLow, Pillar: model.PillarCostOptimization, ResourceTypes: []string{"aws_redshift_cluster"}}
}

func (r *Tags) Evaluate(resource model.TerraformResource) []model.Finding {
	if _, ok := resource.Attributes["tags"]; ok {
		return nil
	}
	return []model.Finding{{RuleID: "RS-007", RuleName: r.Metadata().Name, Severity: model.SeverityLow, Pillar: model.PillarCostOptimization, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "Redshift cluster does not have tags configured.", Remediation: "Add tags for cost allocation and resource organization."}}
}
