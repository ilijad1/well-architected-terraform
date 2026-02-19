package bedrock

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&GuardrailBlockedMessaging{})
}

type GuardrailBlockedMessaging struct{}

func (r *GuardrailBlockedMessaging) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "BRK-003",
		Name:          "Bedrock Guardrail Blocked Messaging",
		Description:   "Bedrock guardrails should have blocked input and output messaging configured.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_bedrock_guardrail"},
	}
}

func (r *GuardrailBlockedMessaging) Evaluate(resource model.TerraformResource) []model.Finding {
	inputMsg, hasInput := resource.GetStringAttr("blocked_input_messaging")
	outputMsg, hasOutput := resource.GetStringAttr("blocked_output_messaging")
	if hasInput && inputMsg != "" && hasOutput && outputMsg != "" {
		return nil
	}
	return []model.Finding{{
		RuleID:      "BRK-003",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "Bedrock guardrail does not have blocked messaging configured",
		Remediation: "Set blocked_input_messaging and blocked_output_messaging",
	}}
}
