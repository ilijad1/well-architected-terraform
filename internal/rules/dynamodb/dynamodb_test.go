package dynamodb

import (
	"testing"

	"github.com/ilijad1/well-architected-terraform/internal/model"
	"github.com/stretchr/testify/assert"
)

// EncryptionRule Tests
func TestEncryptionRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_dynamodb_table",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks: map[string][]model.Block{
			"server_side_encryption": {{
				Type: "server_side_encryption",
				Attributes: map[string]interface{}{
					"enabled": true,
				},
			}},
		},
	}
	rule := &EncryptionRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestEncryptionRule_Fail_NoBlock(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_dynamodb_table",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &EncryptionRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "DDB-001", findings[0].RuleID)
}

func TestEncryptionRule_Fail_NotEnabled(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_dynamodb_table",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks: map[string][]model.Block{
			"server_side_encryption": {{
				Type: "server_side_encryption",
				Attributes: map[string]interface{}{
					"enabled": false,
				},
			}},
		},
	}
	rule := &EncryptionRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "DDB-001", findings[0].RuleID)
}

// PITRRule Tests
func TestPITRRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_dynamodb_table",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks: map[string][]model.Block{
			"point_in_time_recovery": {{
				Type: "point_in_time_recovery",
				Attributes: map[string]interface{}{
					"enabled": true,
				},
			}},
		},
	}
	rule := &PITRRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestPITRRule_Fail_NoBlock(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_dynamodb_table",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &PITRRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "DDB-002", findings[0].RuleID)
}

func TestPITRRule_Fail_NotEnabled(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_dynamodb_table",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks: map[string][]model.Block{
			"point_in_time_recovery": {{
				Type: "point_in_time_recovery",
				Attributes: map[string]interface{}{
					"enabled": false,
				},
			}},
		},
	}
	rule := &PITRRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "DDB-002", findings[0].RuleID)
}

// DeletionProtectionRule Tests
func TestDeletionProtectionRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_dynamodb_table",
		Name: "test",
		Attributes: map[string]interface{}{
			"deletion_protection_enabled": true,
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &DeletionProtectionRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestDeletionProtectionRule_Fail_NotSet(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_dynamodb_table",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &DeletionProtectionRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "DDB-003", findings[0].RuleID)
}

func TestDeletionProtectionRule_Fail_False(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_dynamodb_table",
		Name: "test",
		Attributes: map[string]interface{}{
			"deletion_protection_enabled": false,
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &DeletionProtectionRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "DDB-003", findings[0].RuleID)
}

// TagsRule Tests
func TestTagsRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_dynamodb_table",
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
		Type:       "aws_dynamodb_table",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &TagsRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "DDB-004", findings[0].RuleID)
}

// Autoscaling Tests
func TestAutoscaling_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_appautoscaling_target",
		Name: "test",
		Attributes: map[string]interface{}{
			"service_namespace": "dynamodb",
			"min_capacity":      float64(5),
			"max_capacity":      float64(100),
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &Autoscaling{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestAutoscaling_Fail_NoCapacity(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_appautoscaling_target",
		Name: "test",
		Attributes: map[string]interface{}{
			"service_namespace": "dynamodb",
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &Autoscaling{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "DDB-005", findings[0].RuleID)
}

func TestAutoscaling_Skip_NonDynamoDB(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_appautoscaling_target",
		Name: "test",
		Attributes: map[string]interface{}{
			"service_namespace": "ecs",
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &Autoscaling{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestKMSCustomerManagedKey_NoCMK(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_dynamodb_table",
		Name:       "no_cmk",
		Attributes: map[string]interface{}{},
		Blocks: map[string][]model.Block{
			"server_side_encryption": {{
				Type: "server_side_encryption",
				Attributes: map[string]interface{}{
					"enabled": true,
				},
			}},
		},
	}
	findings := (&KMSCustomerManagedKey{}).Evaluate(resource)
	assert.Len(t, findings, 1)
	assert.Equal(t, "DDB-006", findings[0].RuleID)
}

func TestKMSCustomerManagedKey_WithCMK(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_dynamodb_table",
		Name:       "with_cmk",
		Attributes: map[string]interface{}{},
		Blocks: map[string][]model.Block{
			"server_side_encryption": {{
				Type: "server_side_encryption",
				Attributes: map[string]interface{}{
					"enabled":     true,
					"kms_key_arn": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234",
				},
			}},
		},
	}
	findings := (&KMSCustomerManagedKey{}).Evaluate(resource)
	assert.Empty(t, findings)
}
