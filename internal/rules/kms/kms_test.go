package kms

import (
	"testing"

	"github.com/ilijad1/well-architected-terraform/internal/model"
	"github.com/stretchr/testify/assert"
)

// KeyRotationRule Tests
func TestKeyRotationRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_kms_key",
		Name: "test",
		Attributes: map[string]interface{}{
			"enable_key_rotation": true,
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &KeyRotationRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestKeyRotationRule_Fail(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_kms_key",
		Name: "test",
		Attributes: map[string]interface{}{
			"enable_key_rotation": false,
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &KeyRotationRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "KMS-001", findings[0].RuleID)
}

// DeletionWindowRule Tests
func TestDeletionWindowRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_kms_key",
		Name: "test",
		Attributes: map[string]interface{}{
			"deletion_window_in_days": float64(30),
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &DeletionWindowRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestDeletionWindowRule_Fail(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_kms_key",
		Name: "test",
		Attributes: map[string]interface{}{
			"deletion_window_in_days": float64(7),
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &DeletionWindowRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "KMS-002", findings[0].RuleID)
}

func TestDeletionWindowRule_Pass_NotSet(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_kms_key",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &DeletionWindowRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

// TagsRule Tests
func TestKMSTagsRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_kms_key",
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

func TestKMSTagsRule_Fail(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_kms_key",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &TagsRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "KMS-003", findings[0].RuleID)
}
