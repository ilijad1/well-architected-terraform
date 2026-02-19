// Package elasticache contains Well-Architected rules for AWS ELASTICACHE resources.
package elasticache

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&AtRestEncryptionRule{})
}

type AtRestEncryptionRule struct{}

func (r *AtRestEncryptionRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "EC-001",
		Name:          "ElastiCache replication group should have at-rest encryption enabled",
		Description:   "Ensures ElastiCache replication groups have at-rest encryption enabled to protect data.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_elasticache_replication_group"},
		DocURL:        "https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/at-rest-encryption.html",
	}
}

func (r *AtRestEncryptionRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	atRestEncryption, exists := resource.GetBoolAttr("at_rest_encryption_enabled")
	if !exists || !atRestEncryption {
		findings = append(findings, model.Finding{
			RuleID:      "EC-001",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityHigh,
			Pillar:      model.PillarSecurity,
			Resource:    resource.FullAddress,
			File:        resource.File,
			Line:        resource.Line,
			Description: "ElastiCache replication group does not have at-rest encryption enabled",
			Remediation: "Set at_rest_encryption_enabled to true",
			DocURL:      r.Metadata().DocURL,
		})
	}

	return findings
}
