package apigateway

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&V2StageLoggingRule{})
}

type V2StageLoggingRule struct{}

func (r *V2StageLoggingRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "APIGW-003",
		Name:          "API Gateway V2 Stage Logging",
		Description:   "API Gateway V2 stages should have access logging enabled",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarOperationalExcellence,
		ResourceTypes: []string{"aws_apigatewayv2_stage"},
		DocURL:        "https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-logging.html",
	}
}

func (r *V2StageLoggingRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	if !resource.HasBlock("access_log_settings") {
		findings = append(findings, model.Finding{
			RuleID:      "APIGW-003",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarOperationalExcellence,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "API Gateway V2 stage does not have access logging enabled",
			Remediation: "Add access_log_settings block to enable access logging",
		})
	}

	return findings
}
