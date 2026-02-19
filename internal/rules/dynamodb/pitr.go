package dynamodb

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&PITRRule{})
}

type PITRRule struct{}

func (r *PITRRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "DDB-002",
		Name:          "DynamoDB table should have point-in-time recovery enabled",
		Description:   "Ensures DynamoDB tables have point-in-time recovery enabled for data protection and disaster recovery",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarReliability,
		ResourceTypes: []string{"aws_dynamodb_table"},
		DocURL:        "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery.html",
	}
}

func (r *PITRRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	if !resource.HasBlock("point_in_time_recovery") {
		findings = append(findings, model.Finding{
			RuleID:      "DDB-002",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityHigh,
			Pillar:      model.PillarReliability,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "DynamoDB table does not have point-in-time recovery configured",
			Remediation: "Add a point_in_time_recovery block with enabled = true to enable continuous backups",
			DocURL:      r.Metadata().DocURL,
		})
		return findings
	}

	// Check if enabled is set to true
	pitrBlocks := resource.GetBlocks("point_in_time_recovery")
	hasRecovery := false

	for _, block := range pitrBlocks {
		if enabled, ok := block.GetBoolAttr("enabled"); ok && enabled {
			hasRecovery = true
			break
		}
	}

	if !hasRecovery {
		findings = append(findings, model.Finding{
			RuleID:      "DDB-002",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityHigh,
			Pillar:      model.PillarReliability,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "DynamoDB table has point-in-time recovery disabled",
			Remediation: "Set enabled = true in the point_in_time_recovery block",
			DocURL:      r.Metadata().DocURL,
		})
	}

	return findings
}
