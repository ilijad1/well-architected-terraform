package cloudfront

import (
	"testing"

	"github.com/ilijad1/well-architected-terraform/internal/model"
	"github.com/stretchr/testify/assert"
)

// TLSVersionRule Tests
func TestTLSVersionRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_cloudfront_distribution",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks: map[string][]model.Block{
			"viewer_certificate": {{
				Type: "viewer_certificate",
				Attributes: map[string]interface{}{
					"minimum_protocol_version": "TLSv1.2_2021",
				},
				Blocks: map[string][]model.Block{},
			}},
		},
	}
	rule := &TLSVersionRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestTLSVersionRule_Fail(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_cloudfront_distribution",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks: map[string][]model.Block{
			"viewer_certificate": {{
				Type: "viewer_certificate",
				Attributes: map[string]interface{}{
					"minimum_protocol_version": "TLSv1",
				},
				Blocks: map[string][]model.Block{},
			}},
		},
	}
	rule := &TLSVersionRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
}

// HTTPSOnlyRule Tests
func TestHTTPSOnlyRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_cloudfront_distribution",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks: map[string][]model.Block{
			"default_cache_behavior": {{
				Type: "default_cache_behavior",
				Attributes: map[string]interface{}{
					"viewer_protocol_policy": "redirect-to-https",
				},
				Blocks: map[string][]model.Block{},
			}},
		},
	}
	rule := &HTTPSOnlyRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestHTTPSOnlyRule_Fail(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_cloudfront_distribution",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks: map[string][]model.Block{
			"default_cache_behavior": {{
				Type: "default_cache_behavior",
				Attributes: map[string]interface{}{
					"viewer_protocol_policy": "allow-all",
				},
				Blocks: map[string][]model.Block{},
			}},
		},
	}
	rule := &HTTPSOnlyRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
}

// WAFRule Tests
func TestWAFRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_cloudfront_distribution",
		Name: "test",
		Attributes: map[string]interface{}{
			"web_acl_id": "arn:aws:waf::123456789012:webacl/example",
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &WAFRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestWAFRule_Fail(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_cloudfront_distribution",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &WAFRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
}

// AccessLoggingRule Tests
func TestAccessLoggingRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_cloudfront_distribution",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks: map[string][]model.Block{
			"logging_config": {{
				Type:       "logging_config",
				Attributes: map[string]interface{}{},
				Blocks:     map[string][]model.Block{},
			}},
		},
	}
	rule := &AccessLoggingRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestAccessLoggingRule_Fail(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_cloudfront_distribution",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &AccessLoggingRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
}

// CompressionRule Tests
func TestCompressionRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_cloudfront_distribution",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks: map[string][]model.Block{
			"default_cache_behavior": {{
				Type: "default_cache_behavior",
				Attributes: map[string]interface{}{
					"compress": true,
				},
				Blocks: map[string][]model.Block{},
			}},
		},
	}
	rule := &CompressionRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestCompressionRule_Fail(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_cloudfront_distribution",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks: map[string][]model.Block{
			"default_cache_behavior": {{
				Type: "default_cache_behavior",
				Attributes: map[string]interface{}{
					"compress": false,
				},
				Blocks: map[string][]model.Block{},
			}},
		},
	}
	rule := &CompressionRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
}

// OriginAccess Tests
func TestOriginAccess_Pass_OAC(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_cloudfront_distribution",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks: map[string][]model.Block{
			"origin": {{
				Type: "origin",
				Attributes: map[string]interface{}{
					"origin_access_control_id": "E2QWRUHAPOMQZL",
				},
				Blocks: map[string][]model.Block{},
			}},
		},
	}
	rule := &OriginAccess{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestOriginAccess_Pass_OAI(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_cloudfront_distribution",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks: map[string][]model.Block{
			"origin": {{
				Type:       "origin",
				Attributes: map[string]interface{}{},
				Blocks: map[string][]model.Block{
					"s3_origin_config": {{
						Type: "s3_origin_config",
						Attributes: map[string]interface{}{
							"origin_access_identity": "origin-access-identity/cloudfront/E2QWRUHAPOMQZL",
						},
						Blocks: map[string][]model.Block{},
					}},
				},
			}},
		},
	}
	rule := &OriginAccess{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestOriginAccess_Fail(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_cloudfront_distribution",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks: map[string][]model.Block{
			"origin": {{
				Type:       "origin",
				Attributes: map[string]interface{}{},
				Blocks:     map[string][]model.Block{},
			}},
		},
	}
	rule := &OriginAccess{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "CF-006", findings[0].RuleID)
}
