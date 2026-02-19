package bedrock

import (
	"testing"

	"github.com/ilijad1/well-architected-terraform/internal/model"
	"github.com/stretchr/testify/assert"
)

// LoggingDestinationRule Tests
func TestLoggingDestinationRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_bedrock_model_invocation_logging_configuration",
		Name: "test",
		Attributes: map[string]interface{}{},
		Blocks: map[string][]model.Block{
			"logging_config": {{
				Type:       "logging_config",
				Attributes: map[string]interface{}{},
				Blocks: map[string][]model.Block{
					"s3_config": {{
						Type: "s3_config",
						Attributes: map[string]interface{}{
							"bucket_name": "logs",
						},
						Blocks: map[string][]model.Block{},
					}},
				},
			}},
		},
	}
	rule := &LoggingDestinationRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestLoggingDestinationRule_Fail(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_bedrock_model_invocation_logging_configuration",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &LoggingDestinationRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "BRK-001", findings[0].RuleID)
}

// TextDataDeliveryRule Tests
func TestTextDataDeliveryRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_bedrock_model_invocation_logging_configuration",
		Name: "test",
		Attributes: map[string]interface{}{},
		Blocks: map[string][]model.Block{
			"logging_config": {{
				Type: "logging_config",
				Attributes: map[string]interface{}{
					"text_data_delivery_enabled": true,
				},
				Blocks: map[string][]model.Block{},
			}},
		},
	}
	rule := &TextDataDeliveryRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestTextDataDeliveryRule_Fail(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_bedrock_model_invocation_logging_configuration",
		Name: "test",
		Attributes: map[string]interface{}{},
		Blocks: map[string][]model.Block{
			"logging_config": {{
				Type: "logging_config",
				Attributes: map[string]interface{}{
					"text_data_delivery_enabled": false,
				},
				Blocks: map[string][]model.Block{},
			}},
		},
	}
	rule := &TextDataDeliveryRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "BRK-002", findings[0].RuleID)
}

// GuardrailBlockedMessaging Tests
func TestGuardrailBlockedMessaging_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_bedrock_guardrail",
		Name: "test",
		Attributes: map[string]interface{}{
			"blocked_input_messaging":  "Your request was blocked.",
			"blocked_output_messaging": "The response was blocked.",
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &GuardrailBlockedMessaging{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestGuardrailBlockedMessaging_Fail_NotSet(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_bedrock_guardrail",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &GuardrailBlockedMessaging{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "BRK-003", findings[0].RuleID)
}

func TestGuardrailBlockedMessaging_Fail_MissingOutput(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_bedrock_guardrail",
		Name: "test",
		Attributes: map[string]interface{}{
			"blocked_input_messaging": "Your request was blocked.",
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &GuardrailBlockedMessaging{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "BRK-003", findings[0].RuleID)
}

func TestGuardrailBlockedMessaging_Fail_EmptyStrings(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_bedrock_guardrail",
		Name: "test",
		Attributes: map[string]interface{}{
			"blocked_input_messaging":  "",
			"blocked_output_messaging": "",
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &GuardrailBlockedMessaging{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "BRK-003", findings[0].RuleID)
}
