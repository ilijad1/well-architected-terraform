package elasticache

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&TagsRule{})
}

type TagsRule struct{}

func (r *TagsRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "EC-006",
		Name:          "ElastiCache replication group tags",
		Description:   "ElastiCache replication groups should have tags for cost allocation.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarCostOptimization,
		ResourceTypes: []string{"aws_elasticache_replication_group"},
	}
}

func (r *TagsRule) Evaluate(resource model.TerraformResource) []model.Finding {
	if _, ok := resource.Attributes["tags"]; ok {
		return nil
	}
	return []model.Finding{{
		RuleID:      "EC-006",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityLow,
		Pillar:      model.PillarCostOptimization,
		Resource:    resource.FullAddress,
		File:        resource.File,
		Line:        resource.Line,
		Description: "ElastiCache replication group does not have tags configured",
		Remediation: "Add tags for cost allocation and resource organization",
	}}
}
