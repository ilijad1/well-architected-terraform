package bedrock

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&TextDataDeliveryRule{})
}

type TextDataDeliveryRule struct{}

func (r *TextDataDeliveryRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "BRK-002",
		Name:          "Bedrock Model Invocation Logging Should Have Text Data Delivery Enabled",
		Description:   "Bedrock model invocation logging should have text data delivery enabled for comprehensive observability into model usage.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarOperationalExcellence,
		ResourceTypes: []string{"aws_bedrock_model_invocation_logging_configuration"},
		DocURL:        "https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html",
	}
}

func (r *TextDataDeliveryRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	// Check if logging_config block exists
	loggingConfigBlocks := resource.GetBlocks("logging_config")
	if len(loggingConfigBlocks) == 0 {
		findings = append(findings, model.Finding{
			RuleID:      r.Metadata().ID,
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarOperationalExcellence,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "Bedrock model invocation logging configuration does not have a logging_config block defined",
			Remediation: "Add a logging_config block with text_data_delivery_enabled = true to enable text data logging",
			DocURL:      "https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html",
		})
		return findings
	}

	// Check text_data_delivery_enabled attribute within logging_config block
	loggingConfig := loggingConfigBlocks[0]
	textDataDelivery, exists := loggingConfig.GetBoolAttr("text_data_delivery_enabled")
	if !exists || !textDataDelivery {
		findings = append(findings, model.Finding{
			RuleID:      r.Metadata().ID,
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarOperationalExcellence,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "Bedrock model invocation logging configuration does not have text data delivery enabled, limiting observability into model usage",
			Remediation: "Set text_data_delivery_enabled = true in the logging_config block to enable comprehensive logging",
			DocURL:      "https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html",
		})
	}

	return findings
}
