package s3

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func newRes(resType, name string, attrs map[string]interface{}) model.TerraformResource {
	return model.TerraformResource{
		Type:       resType,
		Name:       name,
		Attributes: attrs,
		Blocks:     map[string][]model.Block{},
	}
}

// --- S3-009: Cross Public Access Block ---

func TestCrossPublicAccessBlock_Missing(t *testing.T) {
	r := &CrossPublicAccessBlockRule{}
	resources := []model.TerraformResource{
		newRes("aws_s3_bucket", "data", map[string]interface{}{
			"bucket": "my-data-bucket",
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Len(t, findings, 1)
	assert.Equal(t, "S3-009", findings[0].RuleID)
	assert.Equal(t, model.SeverityCritical, findings[0].Severity)
}

func TestCrossPublicAccessBlock_Present(t *testing.T) {
	r := &CrossPublicAccessBlockRule{}
	resources := []model.TerraformResource{
		newRes("aws_s3_bucket", "data", map[string]interface{}{
			"bucket": "my-data-bucket",
		}),
		newRes("aws_s3_bucket_public_access_block", "data_pab", map[string]interface{}{
			"bucket":                  "my-data-bucket",
			"block_public_acls":       true,
			"block_public_policy":     true,
			"ignore_public_acls":      true,
			"restrict_public_buckets": true,
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Empty(t, findings)
}

func TestCrossPublicAccessBlock_MultipleBuckets(t *testing.T) {
	r := &CrossPublicAccessBlockRule{}
	resources := []model.TerraformResource{
		newRes("aws_s3_bucket", "a", map[string]interface{}{"bucket": "bucket-a"}),
		newRes("aws_s3_bucket", "b", map[string]interface{}{"bucket": "bucket-b"}),
		newRes("aws_s3_bucket_public_access_block", "a_pab", map[string]interface{}{"bucket": "bucket-a"}),
	}
	findings := r.EvaluateAll(resources)
	assert.Len(t, findings, 1)
	assert.Contains(t, findings[0].Resource, "b")
}

// --- S3-010: Cross Versioning ---

func TestCrossVersioning_Missing(t *testing.T) {
	r := &CrossVersioningRule{}
	resources := []model.TerraformResource{
		newRes("aws_s3_bucket", "data", map[string]interface{}{
			"bucket": "my-data-bucket",
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Len(t, findings, 1)
	assert.Equal(t, "S3-010", findings[0].RuleID)
}

func TestCrossVersioning_Present(t *testing.T) {
	r := &CrossVersioningRule{}
	resources := []model.TerraformResource{
		newRes("aws_s3_bucket", "data", map[string]interface{}{
			"bucket": "my-data-bucket",
		}),
		newRes("aws_s3_bucket_versioning", "data_ver", map[string]interface{}{
			"bucket": "my-data-bucket",
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Empty(t, findings)
}

// --- S3-011: Cross Access Logging ---

func TestCrossLogging_Missing(t *testing.T) {
	r := &CrossLoggingRule{}
	resources := []model.TerraformResource{
		newRes("aws_s3_bucket", "data", map[string]interface{}{
			"bucket": "my-data-bucket",
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Len(t, findings, 1)
	assert.Equal(t, "S3-011", findings[0].RuleID)
}

func TestCrossLogging_Present(t *testing.T) {
	r := &CrossLoggingRule{}
	resources := []model.TerraformResource{
		newRes("aws_s3_bucket", "data", map[string]interface{}{
			"bucket": "my-data-bucket",
		}),
		newRes("aws_s3_bucket_logging", "data_log", map[string]interface{}{
			"bucket": "my-data-bucket",
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Empty(t, findings)
}

func TestCrossLogging_MultipleBuckets_OneUncovered(t *testing.T) {
	r := &CrossLoggingRule{}
	resources := []model.TerraformResource{
		newRes("aws_s3_bucket", "a", map[string]interface{}{"bucket": "bucket-a"}),
		newRes("aws_s3_bucket", "b", map[string]interface{}{"bucket": "bucket-b"}),
		newRes("aws_s3_bucket_logging", "a_log", map[string]interface{}{"bucket": "bucket-a"}),
	}
	findings := r.EvaluateAll(resources)
	assert.Len(t, findings, 1)
	assert.Contains(t, findings[0].Resource, "b")
}

func TestCrossLogging_NoBuckets(t *testing.T) {
	r := &CrossLoggingRule{}
	findings := r.EvaluateAll(nil)
	assert.Empty(t, findings)
}

// --- S3-012: Cross Encryption Config ---

func TestCrossEncryptionConfig_Missing(t *testing.T) {
	r := &CrossEncryptionConfigRule{}
	resources := []model.TerraformResource{
		newRes("aws_s3_bucket", "data", map[string]interface{}{
			"bucket": "my-data-bucket",
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Len(t, findings, 1)
	assert.Equal(t, "S3-012", findings[0].RuleID)
	assert.Equal(t, model.SeverityHigh, findings[0].Severity)
}

func TestCrossEncryptionConfig_Present(t *testing.T) {
	r := &CrossEncryptionConfigRule{}
	resources := []model.TerraformResource{
		newRes("aws_s3_bucket", "data", map[string]interface{}{
			"bucket": "my-data-bucket",
		}),
		newRes("aws_s3_bucket_server_side_encryption_configuration", "data_enc", map[string]interface{}{
			"bucket": "my-data-bucket",
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Empty(t, findings)
}

func TestCrossEncryptionConfig_MultipleBuckets_OneUncovered(t *testing.T) {
	r := &CrossEncryptionConfigRule{}
	resources := []model.TerraformResource{
		newRes("aws_s3_bucket", "a", map[string]interface{}{"bucket": "bucket-a"}),
		newRes("aws_s3_bucket", "b", map[string]interface{}{"bucket": "bucket-b"}),
		newRes("aws_s3_bucket_server_side_encryption_configuration", "a_enc", map[string]interface{}{"bucket": "bucket-a"}),
	}
	findings := r.EvaluateAll(resources)
	assert.Len(t, findings, 1)
	assert.Contains(t, findings[0].Resource, "b")
}

func TestCrossEncryptionConfig_NoBuckets(t *testing.T) {
	r := &CrossEncryptionConfigRule{}
	findings := r.EvaluateAll(nil)
	assert.Empty(t, findings)
}
