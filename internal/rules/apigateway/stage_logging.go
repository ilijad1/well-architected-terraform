package apigateway

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&StageLoggingRule{})
}

type StageLoggingRule struct{}

func (r *StageLoggingRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "APIGW-001",
		Name:          "API Gateway Stage Logging",
		Description:   "API Gateway stages should have access logging enabled",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarOperationalExcellence,
		ResourceTypes: []string{"aws_api_gateway_stage"},
		DocURL:        "https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html",
	}
}

func (r *StageLoggingRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	if !resource.HasBlock("access_log_settings") {
		findings = append(findings, model.Finding{
			RuleID:      "APIGW-001",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarOperationalExcellence,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "API Gateway stage does not have access logging enabled",
			Remediation: "Add access_log_settings block to enable access logging",
		})
	}

	return findings
}
