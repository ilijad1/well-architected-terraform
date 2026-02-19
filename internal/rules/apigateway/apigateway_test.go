package apigateway

import (
	"testing"

	"github.com/ilijad1/well-architected-terraform/internal/model"
	"github.com/stretchr/testify/assert"
)

// StageLoggingRule Tests
func TestStageLoggingRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_api_gateway_stage",
		Name: "test",
		Attributes: map[string]interface{}{},
		Blocks: map[string][]model.Block{
			"access_log_settings": {{
				Type:       "access_log_settings",
				Attributes: map[string]interface{}{},
				Blocks:     map[string][]model.Block{},
			}},
		},
	}
	rule := &StageLoggingRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestStageLoggingRule_Fail(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_api_gateway_stage",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &StageLoggingRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
}

// XRayTracingRule Tests
func TestXRayTracingRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_api_gateway_stage",
		Name: "test",
		Attributes: map[string]interface{}{
			"xray_tracing_enabled": true,
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &XRayTracingRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestXRayTracingRule_Fail(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_api_gateway_stage",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &XRayTracingRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
}

// V2StageLoggingRule Tests
func TestV2StageLoggingRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_apigatewayv2_stage",
		Name: "test",
		Attributes: map[string]interface{}{},
		Blocks: map[string][]model.Block{
			"access_log_settings": {{
				Type:       "access_log_settings",
				Attributes: map[string]interface{}{},
				Blocks:     map[string][]model.Block{},
			}},
		},
	}
	rule := &V2StageLoggingRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestV2StageLoggingRule_Fail(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_apigatewayv2_stage",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &V2StageLoggingRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
}

func TestWAFEnabled_NoWAF(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_api_gateway_stage",
		Name:       "no_waf",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	findings := (&WAFEnabled{}).Evaluate(resource)
	assert.Len(t, findings, 1)
	assert.Equal(t, "APIGW-005", findings[0].RuleID)
	assert.Equal(t, model.SeverityHigh, findings[0].Severity)
}

func TestWAFEnabled_WithWAF(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_api_gateway_stage",
		Name: "with_waf",
		Attributes: map[string]interface{}{
			"web_acl_arn": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/my-acl/abc123",
		},
		Blocks: map[string][]model.Block{},
	}
	findings := (&WAFEnabled{}).Evaluate(resource)
	assert.Empty(t, findings)
}
