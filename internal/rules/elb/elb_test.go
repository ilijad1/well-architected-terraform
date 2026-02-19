package elb

import (
	"testing"

	"github.com/ilijad1/well-architected-terraform/internal/model"
	"github.com/stretchr/testify/assert"
)

// DropInvalidHeadersRule Tests
func TestDropInvalidHeadersRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_lb",
		Name: "test",
		Attributes: map[string]interface{}{
			"drop_invalid_header_fields": true,
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &DropInvalidHeadersRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestDropInvalidHeadersRule_Fail(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_lb",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &DropInvalidHeadersRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
}

// AccessLogsRule Tests
func TestAccessLogsRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_lb",
		Name: "test",
		Attributes: map[string]interface{}{},
		Blocks: map[string][]model.Block{
			"access_logs": {{
				Type: "access_logs",
				Attributes: map[string]interface{}{
					"enabled": true,
				},
				Blocks: map[string][]model.Block{},
			}},
		},
	}
	rule := &AccessLogsRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestAccessLogsRule_Fail(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_lb",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &AccessLogsRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
}

// DeletionProtectionRule Tests
func TestDeletionProtectionRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_lb",
		Name: "test",
		Attributes: map[string]interface{}{
			"enable_deletion_protection": true,
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &DeletionProtectionRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestDeletionProtectionRule_Fail(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_lb",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &DeletionProtectionRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
}

// HTTPSListenerRule Tests
func TestHTTPSListenerRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_lb_listener",
		Name: "test",
		Attributes: map[string]interface{}{
			"protocol": "HTTPS",
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &HTTPSListenerRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestHTTPSListenerRule_Fail(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_lb_listener",
		Name: "test",
		Attributes: map[string]interface{}{
			"protocol": "HTTP",
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &HTTPSListenerRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
}

// TagsRule Tests
func TestELBTagsRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_lb",
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

func TestELBTagsRule_Fail(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_lb",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &TagsRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
}

// CrossZoneRule Tests
func TestCrossZoneRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_lb",
		Name: "test",
		Attributes: map[string]interface{}{
			"enable_cross_zone_load_balancing": true,
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &CrossZoneRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestCrossZoneRule_Fail(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_lb",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &CrossZoneRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "ELB-006", findings[0].RuleID)
}
