package kinesis

import (
	"testing"

	"github.com/ilijad1/well-architected-terraform/internal/model"
	"github.com/stretchr/testify/assert"
)

// EncryptionRule Tests
func TestEncryptionRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_kinesis_stream",
		Name: "test",
		Attributes: map[string]interface{}{
			"encryption_type": "KMS",
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &EncryptionRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestEncryptionRule_Fail_NotSet(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_kinesis_stream",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &EncryptionRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "KIN-001", findings[0].RuleID)
}

func TestEncryptionRule_Fail_NotKMS(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_kinesis_stream",
		Name: "test",
		Attributes: map[string]interface{}{
			"encryption_type": "NONE",
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &EncryptionRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "KIN-001", findings[0].RuleID)
}

// RetentionRule Tests
func TestRetentionRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_kinesis_stream",
		Name: "test",
		Attributes: map[string]interface{}{
			"retention_period": 48,
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &RetentionRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestRetentionRule_Fail_NotSet(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_kinesis_stream",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &RetentionRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "KIN-002", findings[0].RuleID)
}

func TestRetentionRule_Fail_TooLow(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_kinesis_stream",
		Name: "test",
		Attributes: map[string]interface{}{
			"retention_period": 24,
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &RetentionRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "KIN-002", findings[0].RuleID)
}

func TestRetentionRule_Fail_Exact24(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_kinesis_stream",
		Name: "test",
		Attributes: map[string]interface{}{
			"retention_period": 24,
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &RetentionRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "KIN-002", findings[0].RuleID)
}

// TagsRule Tests
func TestTagsRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_kinesis_stream",
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
		Type:       "aws_kinesis_stream",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &TagsRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "KIN-003", findings[0].RuleID)
}
