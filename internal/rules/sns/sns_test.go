package sns

import (
	"testing"

	"github.com/ilijad1/well-architected-terraform/internal/model"
	"github.com/stretchr/testify/assert"
)

// EncryptionRule Tests
func TestEncryptionRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_sns_topic",
		Name: "test",
		Attributes: map[string]interface{}{
			"kms_master_key_id": "arn:aws:kms:us-east-1:123456789012:key/abc123",
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &EncryptionRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestEncryptionRule_Fail_NotSet(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_sns_topic",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &EncryptionRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "SNS-001", findings[0].RuleID)
}

func TestEncryptionRule_Fail_Empty(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_sns_topic",
		Name: "test",
		Attributes: map[string]interface{}{
			"kms_master_key_id": "",
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &EncryptionRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "SNS-001", findings[0].RuleID)
}

// TagsRule Tests
func TestTagsRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_sns_topic",
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
		Type:       "aws_sns_topic",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &TagsRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "SNS-002", findings[0].RuleID)
}

// SubscriptionDLQRule Tests
func TestSubscriptionDLQRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_sns_topic_subscription",
		Name: "test",
		Attributes: map[string]interface{}{
			"redrive_policy": "{\"deadLetterTargetArn\":\"arn:aws:sqs:us-east-1:123456789012:dlq\"}",
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &SubscriptionDLQRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestSubscriptionDLQRule_Fail_NotSet(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_sns_topic_subscription",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &SubscriptionDLQRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "SNS-003", findings[0].RuleID)
}

func TestSubscriptionDLQRule_Fail_Empty(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_sns_topic_subscription",
		Name: "test",
		Attributes: map[string]interface{}{
			"redrive_policy": "",
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &SubscriptionDLQRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "SNS-003", findings[0].RuleID)
}

// PublicPolicy Tests
func TestPublicPolicy_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_sns_topic_policy",
		Name: "test",
		Attributes: map[string]interface{}{
			"policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::123456789012:root\"},\"Action\":\"SNS:Publish\",\"Resource\":\"*\"}]}",
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &PublicPolicy{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestPublicPolicy_Fail(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_sns_topic_policy",
		Name: "test",
		Attributes: map[string]interface{}{
			"policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"SNS:Publish\",\"Resource\":\"*\"}]}",
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &PublicPolicy{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "SNS-004", findings[0].RuleID)
}

func TestPublicPolicy_Fail_WithSpace(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_sns_topic_policy",
		Name: "test",
		Attributes: map[string]interface{}{
			"policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\": \"*\",\"Action\":\"SNS:Publish\",\"Resource\":\"*\"}]}",
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &PublicPolicy{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "SNS-004", findings[0].RuleID)
}
