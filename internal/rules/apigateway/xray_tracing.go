package apigateway

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&XRayTracingRule{})
}

type XRayTracingRule struct{}

func (r *XRayTracingRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "APIGW-002",
		Name:          "API Gateway X-Ray Tracing",
		Description:   "API Gateway stages should have X-Ray tracing enabled",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarOperationalExcellence,
		ResourceTypes: []string{"aws_api_gateway_stage"},
		DocURL:        "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-xray.html",
	}
}

func (r *XRayTracingRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	xrayEnabled, exists := resource.GetBoolAttr("xray_tracing_enabled")
	if !exists || !xrayEnabled {
		findings = append(findings, model.Finding{
			RuleID:      "APIGW-002",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarOperationalExcellence,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "API Gateway stage does not have X-Ray tracing enabled",
			Remediation: "Set xray_tracing_enabled to true to enable distributed tracing",
		})
	}

	return findings
}
