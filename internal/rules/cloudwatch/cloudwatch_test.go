package cloudwatch

import (
	"testing"

	"github.com/ilijad1/well-architected-terraform/internal/model"
	"github.com/stretchr/testify/assert"
)

// LogRetentionRule Tests
func TestLogRetentionRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_cloudwatch_log_group",
		Name: "test",
		Attributes: map[string]interface{}{
			"retention_in_days": float64(30),
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &LogRetentionRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestLogRetentionRule_Fail(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_cloudwatch_log_group",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &LogRetentionRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
}

// LogEncryptionRule Tests
func TestLogEncryptionRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_cloudwatch_log_group",
		Name: "test",
		Attributes: map[string]interface{}{
			"kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/example",
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &LogEncryptionRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestLogEncryptionRule_Fail(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_cloudwatch_log_group",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &LogEncryptionRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
}

// TagsRule Tests
func TestCWTagsRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_cloudwatch_log_group",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks: map[string][]model.Block{
			"tags": {{
				Type: "tags",
				Attributes: map[string]interface{}{
					"Environment": "production",
				},
				Blocks: map[string][]model.Block{},
			}},
		},
	}
	rule := &TagsRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestCWTagsRule_Fail(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_cloudwatch_log_group",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &TagsRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
}

// AlarmActionsRule Tests
func TestAlarmActionsRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_cloudwatch_metric_alarm",
		Name: "test",
		Attributes: map[string]interface{}{
			"alarm_actions": []interface{}{"arn:aws:sns:us-east-1:123456789012:my-topic"},
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &AlarmActionsRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestAlarmActionsRule_Fail_Empty(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_cloudwatch_metric_alarm",
		Name: "test",
		Attributes: map[string]interface{}{
			"alarm_actions": []interface{}{},
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &AlarmActionsRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "CW-004", findings[0].RuleID)
}

func TestAlarmActionsRule_Fail_NotSet(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_cloudwatch_metric_alarm",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &AlarmActionsRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "CW-004", findings[0].RuleID)
}
