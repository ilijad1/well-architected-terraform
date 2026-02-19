package sustainability

import (
	"strings"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// GravitonElastiCacheRule checks if ElastiCache uses Graviton node types.
type GravitonElastiCacheRule struct{}

func init() {
	engine.Register(&GravitonElastiCacheRule{})
}

func (r *GravitonElastiCacheRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "SUS-003",
		Name:          "ElastiCache Not Using Graviton",
		Description:   "ElastiCache replication groups should use Graviton-based node types for better energy efficiency.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarSustainability,
		ResourceTypes: []string{"aws_elasticache_replication_group"},
	}
}

func (r *GravitonElastiCacheRule) Evaluate(resource model.TerraformResource) []model.Finding {
	nodeType, ok := resource.GetStringAttr("node_type")
	if !ok || nodeType == "" {
		return nil
	}

	// cache.m7g.large, cache.r7g.xlarge — Graviton
	parts := strings.Split(nodeType, ".")
	if len(parts) >= 2 {
		family := parts[1]
		if strings.HasSuffix(family, "g") || strings.HasSuffix(family, "gd") {
			return nil
		}
	}

	return []model.Finding{{
		RuleID:      "SUS-003",
		RuleName:    "ElastiCache Not Using Graviton",
		Severity:    model.SeverityLow,
		Pillar:      model.PillarSustainability,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "ElastiCache node type " + nodeType + " is not Graviton-based. Graviton nodes are more energy-efficient.",
		Remediation: "Consider migrating to a Graviton node type (e.g., cache.m7g, cache.r7g). Verify application compatibility.",
	}}
}
