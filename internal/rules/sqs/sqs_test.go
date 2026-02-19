package sqs

import (
	"testing"

	"github.com/ilijad1/well-architected-terraform/internal/model"
	"github.com/stretchr/testify/assert"
)

// EncryptionRule Tests
func TestEncryptionRule_Pass_KMS(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_sqs_queue",
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

func TestEncryptionRule_Pass_SQSSSE(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_sqs_queue",
		Name: "test",
		Attributes: map[string]interface{}{
			"sqs_managed_sse_enabled": true,
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &EncryptionRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestEncryptionRule_Fail_NoEncryption(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_sqs_queue",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &EncryptionRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "SQS-001", findings[0].RuleID)
}

func TestEncryptionRule_Fail_SSEDisabled(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_sqs_queue",
		Name: "test",
		Attributes: map[string]interface{}{
			"sqs_managed_sse_enabled": false,
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &EncryptionRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "SQS-001", findings[0].RuleID)
}

// DeadLetterRule Tests
func TestDeadLetterRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_sqs_queue",
		Name: "test",
		Attributes: map[string]interface{}{
			"redrive_policy": "{\"deadLetterTargetArn\":\"arn:aws:sqs:us-east-1:123456789012:dlq\",\"maxReceiveCount\":3}",
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &DeadLetterRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestDeadLetterRule_Fail_NotSet(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_sqs_queue",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &DeadLetterRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "SQS-002", findings[0].RuleID)
}

func TestDeadLetterRule_Fail_Empty(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_sqs_queue",
		Name: "test",
		Attributes: map[string]interface{}{
			"redrive_policy": "",
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &DeadLetterRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "SQS-002", findings[0].RuleID)
}

// TagsRule Tests
func TestTagsRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_sqs_queue",
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
		Type:       "aws_sqs_queue",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &TagsRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "SQS-003", findings[0].RuleID)
}

// VisibilityTimeout Tests
func TestVisibilityTimeout_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_sqs_queue",
		Name: "test",
		Attributes: map[string]interface{}{
			"visibility_timeout_seconds": float64(30),
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &VisibilityTimeout{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestVisibilityTimeout_Fail_TooLow(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_sqs_queue",
		Name: "test",
		Attributes: map[string]interface{}{
			"visibility_timeout_seconds": float64(10),
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &VisibilityTimeout{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "SQS-004", findings[0].RuleID)
}

func TestVisibilityTimeout_Fail_NotSet(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_sqs_queue",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &VisibilityTimeout{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "SQS-004", findings[0].RuleID)
}

// --- SQS-005: Cross DLQ ---

func makeSQSRes(resType, name string, attrs map[string]interface{}) model.TerraformResource {
	return model.TerraformResource{
		Type:       resType,
		Name:       name,
		Attributes: attrs,
		Blocks:     map[string][]model.Block{},
	}
}

func TestCrossDLQ_QueueWithNoDLQInPlan(t *testing.T) {
	r := &CrossDLQRule{}
	resources := []model.TerraformResource{
		makeSQSRes("aws_sqs_queue", "main", map[string]interface{}{
			"name":            "main-queue",
			"redrive_policy":  `{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:123456789012:external-dlq","maxReceiveCount":5}`,
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Len(t, findings, 1)
	assert.Equal(t, "SQS-005", findings[0].RuleID)
}

func TestCrossDLQ_QueueWithDLQInPlan(t *testing.T) {
	r := &CrossDLQRule{}
	resources := []model.TerraformResource{
		makeSQSRes("aws_sqs_queue", "main", map[string]interface{}{
			"name":           "main-queue",
			"redrive_policy": `{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:123456789012:my-dlq","maxReceiveCount":5}`,
		}),
		makeSQSRes("aws_sqs_queue", "dlq", map[string]interface{}{
			"name": "my-dlq",
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Empty(t, findings)
}

func TestCrossDLQ_QueueWithNoRedrivePolicy(t *testing.T) {
	r := &CrossDLQRule{}
	resources := []model.TerraformResource{
		makeSQSRes("aws_sqs_queue", "main", map[string]interface{}{
			"name": "main-queue",
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Empty(t, findings)
}

func TestCrossDLQ_NoQueues(t *testing.T) {
	r := &CrossDLQRule{}
	findings := r.EvaluateAll(nil)
	assert.Empty(t, findings)
}
