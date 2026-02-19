package elasticache

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&TransitEncryptionRule{})
}

type TransitEncryptionRule struct{}

func (r *TransitEncryptionRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "EC-002",
		Name:          "ElastiCache replication group should have transit encryption enabled",
		Description:   "Ensures ElastiCache replication groups have transit encryption enabled to protect data in transit.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_elasticache_replication_group"},
		DocURL:        "https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/in-transit-encryption.html",
	}
}

func (r *TransitEncryptionRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	transitEncryption, exists := resource.GetBoolAttr("transit_encryption_enabled")
	if !exists || !transitEncryption {
		findings = append(findings, model.Finding{
			RuleID:      "EC-002",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityHigh,
			Pillar:      model.PillarSecurity,
			Resource:    resource.FullAddress,
			File:        resource.File,
			Line:        resource.Line,
			Description: "ElastiCache replication group does not have transit encryption enabled",
			Remediation: "Set transit_encryption_enabled to true",
			DocURL:      r.Metadata().DocURL,
		})
	}

	return findings
}
