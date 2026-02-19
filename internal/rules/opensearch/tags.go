package opensearch

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&Tags{})
}

type Tags struct{}

func (r *Tags) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "OS-008", Name: "OpenSearch Domain Tags", Description: "OpenSearch domains should have tags for cost allocation.", Severity: model.SeverityLow, Pillar: model.PillarCostOptimization, ResourceTypes: []string{"aws_opensearch_domain"}}
}

func (r *Tags) Evaluate(resource model.TerraformResource) []model.Finding {
	if _, ok := resource.Attributes["tags"]; ok {
		return nil
	}
	return []model.Finding{{RuleID: "OS-008", RuleName: r.Metadata().Name, Severity: model.SeverityLow, Pillar: model.PillarCostOptimization, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "OpenSearch domain does not have tags configured.", Remediation: "Add tags for cost allocation and resource organization."}}
}
