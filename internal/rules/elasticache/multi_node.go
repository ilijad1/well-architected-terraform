package elasticache

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&MultiNodeRule{})
}

type MultiNodeRule struct{}

func (r *MultiNodeRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "EC-004",
		Name:          "ElastiCache replication group should have multiple cache clusters",
		Description:   "Ensures ElastiCache replication groups have multiple cache clusters for high availability.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarReliability,
		ResourceTypes: []string{"aws_elasticache_replication_group"},
		DocURL:        "https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/Replication.html",
	}
}

func (r *MultiNodeRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	numClusters, exists := resource.GetNumberAttr("num_cache_clusters")
	if !exists || numClusters <= 1 {
		findings = append(findings, model.Finding{
			RuleID:      "EC-004",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarReliability,
			Resource:    resource.FullAddress,
			File:        resource.File,
			Line:        resource.Line,
			Description: "ElastiCache replication group does not have multiple cache clusters configured",
			Remediation: "Set num_cache_clusters to a value greater than 1 for high availability",
			DocURL:      r.Metadata().DocURL,
		})
	}

	return findings
}
