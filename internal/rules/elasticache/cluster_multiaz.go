package elasticache

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&ClusterMultiAZ{})
}

// ClusterMultiAZ checks that ElastiCache clusters are configured for multi-AZ high availability.
type ClusterMultiAZ struct{}

func (r *ClusterMultiAZ) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "EC-007",
		Name:          "ElastiCache Cluster Multi-AZ",
		Description:   "ElastiCache clusters should use cross-AZ mode with multiple nodes for high availability.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarReliability,
		ResourceTypes: []string{"aws_elasticache_cluster"},
		DocURL:        "https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/AutoFailover.html",
	}
}

func (r *ClusterMultiAZ) Evaluate(resource model.TerraformResource) []model.Finding {
	azMode, hasAZMode := resource.GetStringAttr("az_mode")
	numNodes, hasNumNodes := resource.GetNumberAttr("num_cache_nodes")

	if hasAZMode && azMode == "cross-az" && hasNumNodes && numNodes > 1 {
		return nil
	}
	return []model.Finding{{
		RuleID:      "EC-007",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarReliability,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "ElastiCache cluster is not configured for multi-AZ high availability (requires az_mode = \"cross-az\" and num_cache_nodes > 1).",
		Remediation: "Set az_mode = \"cross-az\" and num_cache_nodes > 1 to enable cross-AZ redundancy.",
		DocURL:      r.Metadata().DocURL,
	}}
}
