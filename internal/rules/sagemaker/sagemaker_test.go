package sagemaker

import (
	"testing"

	"github.com/ilijad1/well-architected-terraform/internal/model"
	"github.com/stretchr/testify/assert"
)

// NotebookEncryptionRule Tests
func TestNotebookEncryptionRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_sagemaker_notebook_instance",
		Name: "test",
		Attributes: map[string]interface{}{
			"kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/example",
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &NotebookEncryptionRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestNotebookEncryptionRule_Fail(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_sagemaker_notebook_instance",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &NotebookEncryptionRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "SM-001", findings[0].RuleID)
}

// NotebookDirectInternetRule Tests
func TestNotebookDirectInternetRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_sagemaker_notebook_instance",
		Name: "test",
		Attributes: map[string]interface{}{
			"direct_internet_access": "Disabled",
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &NotebookDirectInternetRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestNotebookDirectInternetRule_Fail(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_sagemaker_notebook_instance",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &NotebookDirectInternetRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "SM-002", findings[0].RuleID)
}

// NotebookRootAccessRule Tests
func TestNotebookRootAccessRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_sagemaker_notebook_instance",
		Name: "test",
		Attributes: map[string]interface{}{
			"root_access": "Disabled",
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &NotebookRootAccessRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestNotebookRootAccessRule_Fail(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_sagemaker_notebook_instance",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &NotebookRootAccessRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "SM-003", findings[0].RuleID)
}

// EndpointEncryptionRule Tests
func TestEndpointEncryptionRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_sagemaker_endpoint_configuration",
		Name: "test",
		Attributes: map[string]interface{}{
			"kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/example",
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &EndpointEncryptionRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestEndpointEncryptionRule_Fail(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_sagemaker_endpoint_configuration",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &EndpointEncryptionRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "SM-004", findings[0].RuleID)
}

// NotebookVPC Tests
func TestNotebookVPC_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_sagemaker_notebook_instance",
		Name: "test",
		Attributes: map[string]interface{}{
			"subnet_id": "subnet-12345",
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &NotebookVPC{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestNotebookVPC_Fail(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_sagemaker_notebook_instance",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &NotebookVPC{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "SM-005", findings[0].RuleID)
}
