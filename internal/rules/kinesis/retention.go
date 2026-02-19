package kinesis

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&RetentionRule{})
}

type RetentionRule struct{}

func (r *RetentionRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "KIN-002",
		Name:          "Kinesis stream should have retention period greater than 24 hours",
		Description:   "Ensures Kinesis streams have adequate data retention for reliability and recovery.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarReliability,
		ResourceTypes: []string{"aws_kinesis_stream"},
		DocURL:        "https://docs.aws.amazon.com/streams/latest/dev/kinesis-extended-retention.html",
	}
}

func (r *RetentionRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	retentionPeriod, exists := resource.GetNumberAttr("retention_period")
	if !exists || retentionPeriod <= 24 {
		findings = append(findings, model.Finding{
			RuleID:      "KIN-002",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityLow,
			Pillar:      model.PillarReliability,
			Resource:    resource.FullAddress,
			File:        resource.File,
			Line:        resource.Line,
			Description: "Kinesis stream retention period is not greater than 24 hours",
			Remediation: "Set retention_period to a value greater than 24",
			DocURL:      r.Metadata().DocURL,
		})
	}

	return findings
}
