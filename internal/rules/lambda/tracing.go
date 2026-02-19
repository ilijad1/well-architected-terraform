package lambda

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&TracingRule{})
}

type TracingRule struct{}

func (r *TracingRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "LAM-001",
		Name:          "Lambda X-Ray Tracing Enabled",
		Description:   "Ensures Lambda functions have X-Ray tracing enabled for better observability",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarOperationalExcellence,
		ResourceTypes: []string{"aws_lambda_function"},
		DocURL:        "https://docs.aws.amazon.com/lambda/latest/dg/services-xray.html",
	}
}

func (r *TracingRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	if !resource.HasBlock("tracing_config") {
		findings = append(findings, model.Finding{
			RuleID:      "LAM-001",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarOperationalExcellence,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "Lambda function does not have X-Ray tracing configured",
			Remediation: "Add a tracing_config block with mode = \"Active\" to enable X-Ray tracing for better observability and debugging",
			DocURL:      r.Metadata().DocURL,
		})
		return findings
	}

	// Check if mode is Active
	tracingBlocks := resource.GetBlocks("tracing_config")
	hasActiveMode := false

	for _, block := range tracingBlocks {
		if mode, ok := block.GetStringAttr("mode"); ok && mode == "Active" {
			hasActiveMode = true
			break
		}
	}

	if !hasActiveMode {
		findings = append(findings, model.Finding{
			RuleID:      "LAM-001",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarOperationalExcellence,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "Lambda function has tracing_config but mode is not set to Active",
			Remediation: "Set tracing_config.mode to \"Active\" to enable X-Ray tracing",
			DocURL:      r.Metadata().DocURL,
		})
	}

	return findings
}
