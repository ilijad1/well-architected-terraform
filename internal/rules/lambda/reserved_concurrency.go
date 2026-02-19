package lambda

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&ReservedConcurrency{})
}

type ReservedConcurrency struct{}

func (r *ReservedConcurrency) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "LAM-006",
		Name:          "Lambda Reserved Concurrent Executions",
		Description:   "Lambda functions should have reserved concurrent executions set to prevent throttling.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarReliability,
		ResourceTypes: []string{"aws_lambda_function"},
	}
}

func (r *ReservedConcurrency) Evaluate(resource model.TerraformResource) []model.Finding {
	if _, ok := resource.Attributes["reserved_concurrent_executions"]; ok {
		return nil
	}

	return []model.Finding{{
		RuleID:      "LAM-006",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityLow,
		Pillar:      model.PillarReliability,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "Lambda function does not have reserved concurrent executions configured.",
		Remediation: "Set reserved_concurrent_executions to limit and reserve concurrency for this function.",
	}}
}
