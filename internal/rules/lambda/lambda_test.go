package lambda

import (
	"testing"

	"github.com/ilijad1/well-architected-terraform/internal/model"
	"github.com/stretchr/testify/assert"
)

// TracingRule Tests
func TestTracingRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_lambda_function",
		Name: "test",
		Attributes: map[string]interface{}{},
		Blocks: map[string][]model.Block{
			"tracing_config": {{
				Type: "tracing_config",
				Attributes: map[string]interface{}{
					"mode": "Active",
				},
			}},
		},
	}
	rule := &TracingRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestTracingRule_Fail_NoBlock(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_lambda_function",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &TracingRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "LAM-001", findings[0].RuleID)
}

func TestTracingRule_Fail_PassiveMode(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_lambda_function",
		Name: "test",
		Attributes: map[string]interface{}{},
		Blocks: map[string][]model.Block{
			"tracing_config": {{
				Type: "tracing_config",
				Attributes: map[string]interface{}{
					"mode": "PassThrough",
				},
			}},
		},
	}
	rule := &TracingRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "LAM-001", findings[0].RuleID)
}

// DeadLetterRule Tests
func TestDeadLetterRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_lambda_function",
		Name: "test",
		Attributes: map[string]interface{}{},
		Blocks: map[string][]model.Block{
			"dead_letter_config": {{
				Type: "dead_letter_config",
				Attributes: map[string]interface{}{
					"target_arn": "arn:aws:sqs:us-east-1:123456789012:dlq",
				},
			}},
		},
	}
	rule := &DeadLetterRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestDeadLetterRule_Fail(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_lambda_function",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &DeadLetterRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "LAM-002", findings[0].RuleID)
}

// EnvEncryptionRule Tests
func TestEnvEncryptionRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_lambda_function",
		Name: "test",
		Attributes: map[string]interface{}{
			"kms_key_arn": "arn:aws:kms:us-east-1:123456789012:key/abc123",
		},
		Blocks: map[string][]model.Block{
			"environment": {{
				Type: "environment",
				Attributes: map[string]interface{}{
					"variables": map[string]interface{}{
						"ENV": "production",
					},
				},
			}},
		},
	}
	rule := &EnvEncryptionRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestEnvEncryptionRule_Pass_NoEnvironment(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_lambda_function",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &EnvEncryptionRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestEnvEncryptionRule_Pass_EmptyEnvironment(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_lambda_function",
		Name: "test",
		Attributes: map[string]interface{}{},
		Blocks: map[string][]model.Block{
			"environment": {{
				Type: "environment",
				Attributes: map[string]interface{}{
					"variables": map[string]interface{}{},
				},
			}},
		},
	}
	rule := &EnvEncryptionRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestEnvEncryptionRule_Fail(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_lambda_function",
		Name: "test",
		Attributes: map[string]interface{}{},
		Blocks: map[string][]model.Block{
			"environment": {{
				Type: "environment",
				Attributes: map[string]interface{}{
					"variables": map[string]interface{}{
						"SECRET": "value",
					},
				},
			}},
		},
	}
	rule := &EnvEncryptionRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "LAM-003", findings[0].RuleID)
}

// TagsRule Tests
func TestTagsRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_lambda_function",
		Name: "test",
		Attributes: map[string]interface{}{
			"tags": map[string]interface{}{
				"Environment": "production",
			},
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &TagsRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestTagsRule_Fail(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_lambda_function",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &TagsRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "LAM-004", findings[0].RuleID)
}

func TestPermissionWildcard_WildcardPrincipal(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_lambda_permission",
		Name:       "public",
		Attributes: map[string]interface{}{"principal": "*"},
		Blocks:     map[string][]model.Block{},
	}
	findings := (&PermissionWildcard{}).Evaluate(resource)
	assert.Len(t, findings, 1)
	assert.Equal(t, "LAM-007", findings[0].RuleID)
}

func TestPermissionWildcard_SpecificPrincipal(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_lambda_permission",
		Name:       "specific",
		Attributes: map[string]interface{}{"principal": "apigateway.amazonaws.com"},
		Blocks:     map[string][]model.Block{},
	}
	findings := (&PermissionWildcard{}).Evaluate(resource)
	assert.Empty(t, findings)
}

// --- LAM-008: Cross Log Group ---

func makeLamRes(resType, name string, attrs map[string]interface{}) model.TerraformResource {
	return model.TerraformResource{
		Type:       resType,
		Name:       name,
		Attributes: attrs,
		Blocks:     map[string][]model.Block{},
	}
}

func TestCrossLogGroup_NoLogGroup(t *testing.T) {
	r := &CrossLogGroupRule{}
	resources := []model.TerraformResource{
		makeLamRes("aws_lambda_function", "my_fn", map[string]interface{}{
			"function_name": "my-function",
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Len(t, findings, 1)
	assert.Equal(t, "LAM-008", findings[0].RuleID)
}

func TestCrossLogGroup_WithMatchingLogGroup(t *testing.T) {
	r := &CrossLogGroupRule{}
	resources := []model.TerraformResource{
		makeLamRes("aws_lambda_function", "my_fn", map[string]interface{}{
			"function_name": "my-function",
		}),
		makeLamRes("aws_cloudwatch_log_group", "fn_logs", map[string]interface{}{
			"name": "/aws/lambda/my-function",
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Empty(t, findings)
}

func TestCrossLogGroup_MultipleFunctions_OneUncovered(t *testing.T) {
	r := &CrossLogGroupRule{}
	resources := []model.TerraformResource{
		makeLamRes("aws_lambda_function", "fn1", map[string]interface{}{"function_name": "function-1"}),
		makeLamRes("aws_lambda_function", "fn2", map[string]interface{}{"function_name": "function-2"}),
		makeLamRes("aws_cloudwatch_log_group", "fn1_logs", map[string]interface{}{"name": "/aws/lambda/function-1"}),
	}
	findings := r.EvaluateAll(resources)
	assert.Len(t, findings, 1)
	assert.Contains(t, findings[0].Resource, "fn2")
}

func TestCrossLogGroup_NoFunctions(t *testing.T) {
	r := &CrossLogGroupRule{}
	findings := r.EvaluateAll(nil)
	assert.Empty(t, findings)
}
