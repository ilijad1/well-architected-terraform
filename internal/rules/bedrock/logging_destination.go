package bedrock

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&LoggingDestinationRule{})
}

type LoggingDestinationRule struct{}

func (r *LoggingDestinationRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "BRK-001",
		Name:          "Bedrock Model Invocation Logging Should Have Destination Configured",
		Description:   "Bedrock model invocation logging should have either S3 or CloudWatch destination configured for comprehensive observability.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarOperationalExcellence,
		ResourceTypes: []string{"aws_bedrock_model_invocation_logging_configuration"},
		DocURL:        "https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html",
	}
}

func (r *LoggingDestinationRule) Evaluate(resource model.TerraformResource) []model.Finding {
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
			Remediation: "Add a logging_config block with either s3_config or cloudwatch_config to enable logging",
			DocURL:      "https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html",
		})
		return findings
	}

	// Check if at least one destination (s3_config or cloudwatch_config) is configured
	loggingConfig := loggingConfigBlocks[0]
	hasS3 := len(loggingConfig.Blocks["s3_config"]) > 0
	hasCloudWatch := len(loggingConfig.Blocks["cloudwatch_config"]) > 0

	if !hasS3 && !hasCloudWatch {
		findings = append(findings, model.Finding{
			RuleID:      r.Metadata().ID,
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarOperationalExcellence,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "Bedrock model invocation logging configuration has a logging_config block but no destination (s3_config or cloudwatch_config) is configured",
			Remediation: "Add either s3_config or cloudwatch_config block within logging_config to specify a logging destination",
			DocURL:      "https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html",
		})
	}

	return findings
}
