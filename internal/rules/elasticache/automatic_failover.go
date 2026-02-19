package elasticache

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&AutomaticFailoverRule{})
}

type AutomaticFailoverRule struct{}

func (r *AutomaticFailoverRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "EC-003",
		Name:          "ElastiCache replication group should have automatic failover enabled",
		Description:   "Ensures ElastiCache replication groups have automatic failover enabled for high availability.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarReliability,
		ResourceTypes: []string{"aws_elasticache_replication_group"},
		DocURL:        "https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/AutoFailover.html",
	}
}

func (r *AutomaticFailoverRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	automaticFailover, exists := resource.GetBoolAttr("automatic_failover_enabled")
	if !exists || !automaticFailover {
		findings = append(findings, model.Finding{
			RuleID:      "EC-003",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityHigh,
			Pillar:      model.PillarReliability,
			Resource:    resource.FullAddress,
			File:        resource.File,
			Line:        resource.Line,
			Description: "ElastiCache replication group does not have automatic failover enabled",
			Remediation: "Set automatic_failover_enabled to true",
			DocURL:      r.Metadata().DocURL,
		})
	}

	return findings
}
