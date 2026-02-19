package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func TestLoad_ValidConfig(t *testing.T) {
	content := `version: "1"
suppressions:
  - rule_id: "S3-001"
    resource: "aws_s3_bucket.legacy"
    reason: "Legacy bucket, migrating next quarter"
    expires: "2026-06-01"
  - rule_id: "*"
    resource: "aws_instance.dev"
    reason: "Dev instance, exempt from all rules"
    expires: "2026-12-31"
`
	path := writeTempFile(t, content)

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, "1", cfg.Version)
	assert.Len(t, cfg.Suppressions, 2)
	assert.Equal(t, "S3-001", cfg.Suppressions[0].RuleID)
	assert.Equal(t, "aws_s3_bucket.legacy", cfg.Suppressions[0].Resource)
	assert.Equal(t, "*", cfg.Suppressions[1].RuleID)
}

func TestLoad_FileNotFound(t *testing.T) {
	cfg, err := Load("/nonexistent/.wat.yaml")
	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Empty(t, cfg.Suppressions)
}

func TestLoad_InvalidYAML(t *testing.T) {
	path := writeTempFile(t, "{{invalid yaml")
	_, err := Load(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parsing config file")
}

func TestLoad_MissingRuleID(t *testing.T) {
	content := `suppressions:
  - resource: "aws_s3_bucket.test"
    reason: "test"
    expires: "2026-01-01"
`
	path := writeTempFile(t, content)
	_, err := Load(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rule_id is required")
}

func TestLoad_MissingResource(t *testing.T) {
	content := `suppressions:
  - rule_id: "S3-001"
    reason: "test"
    expires: "2026-01-01"
`
	path := writeTempFile(t, content)
	_, err := Load(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "resource is required")
}

func TestLoad_MissingReason(t *testing.T) {
	content := `suppressions:
  - rule_id: "S3-001"
    resource: "*"
    expires: "2026-01-01"
`
	path := writeTempFile(t, content)
	_, err := Load(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "reason is required")
}

func TestLoad_MissingExpires(t *testing.T) {
	content := `suppressions:
  - rule_id: "S3-001"
    resource: "*"
    reason: "test"
`
	path := writeTempFile(t, content)
	_, err := Load(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expires is required")
}

func TestLoad_EmptyFile(t *testing.T) {
	path := writeTempFile(t, "")
	cfg, err := Load(path)
	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Empty(t, cfg.Suppressions)
}

func TestApply_NoSuppressions(t *testing.T) {
	findings := []model.Finding{
		{RuleID: "S3-001", Resource: "aws_s3_bucket.test"},
	}
	result := Apply(findings, nil, time.Now())
	assert.Len(t, result.Kept, 1)
	assert.Empty(t, result.Suppressed)
	assert.Empty(t, result.ExpiredSuppressions)
}

func TestApply_ExactMatch(t *testing.T) {
	findings := []model.Finding{
		{RuleID: "S3-001", Resource: "aws_s3_bucket.legacy"},
		{RuleID: "S3-002", Resource: "aws_s3_bucket.other"},
	}
	suppressions := []Suppression{
		{RuleID: "S3-001", Resource: "aws_s3_bucket.legacy", Reason: "known", Expires: "2027-01-01"},
	}
	result := Apply(findings, suppressions, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	assert.Len(t, result.Kept, 1)
	assert.Equal(t, "S3-002", result.Kept[0].RuleID)
	assert.Len(t, result.Suppressed, 1)
	assert.Equal(t, "S3-001", result.Suppressed[0].RuleID)
}

func TestApply_WildcardRuleID(t *testing.T) {
	findings := []model.Finding{
		{RuleID: "S3-001", Resource: "aws_s3_bucket.dev"},
		{RuleID: "EC2-001", Resource: "aws_s3_bucket.dev"},
	}
	suppressions := []Suppression{
		{RuleID: "*", Resource: "aws_s3_bucket.dev", Reason: "dev resource", Expires: "2027-01-01"},
	}
	result := Apply(findings, suppressions, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	assert.Empty(t, result.Kept)
	assert.Len(t, result.Suppressed, 2)
}

func TestApply_WildcardResource(t *testing.T) {
	findings := []model.Finding{
		{RuleID: "S3-001", Resource: "aws_s3_bucket.a"},
		{RuleID: "S3-001", Resource: "aws_s3_bucket.b"},
		{RuleID: "EC2-001", Resource: "aws_instance.c"},
	}
	suppressions := []Suppression{
		{RuleID: "S3-001", Resource: "*", Reason: "suppress all S3-001", Expires: "2027-01-01"},
	}
	result := Apply(findings, suppressions, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	assert.Len(t, result.Kept, 1)
	assert.Equal(t, "EC2-001", result.Kept[0].RuleID)
	assert.Len(t, result.Suppressed, 2)
}

func TestApply_ExpiredSuppression(t *testing.T) {
	findings := []model.Finding{
		{RuleID: "S3-001", Resource: "aws_s3_bucket.test"},
	}
	suppressions := []Suppression{
		{RuleID: "S3-001", Resource: "aws_s3_bucket.test", Reason: "old", Expires: "2025-01-01"},
	}
	// The finding is still suppressed, but the suppression is tracked as expired
	result := Apply(findings, suppressions, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	assert.Len(t, result.Suppressed, 1)
	assert.Empty(t, result.Kept)
	assert.Len(t, result.ExpiredSuppressions, 1)
	assert.Equal(t, "2025-01-01", result.ExpiredSuppressions[0].Expires)
}

func TestApply_NoMatch(t *testing.T) {
	findings := []model.Finding{
		{RuleID: "S3-001", Resource: "aws_s3_bucket.test"},
	}
	suppressions := []Suppression{
		{RuleID: "EC2-001", Resource: "aws_instance.other", Reason: "wrong", Expires: "2027-01-01"},
	}
	result := Apply(findings, suppressions, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	assert.Len(t, result.Kept, 1)
	assert.Empty(t, result.Suppressed)
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, ".wat.yaml")
	err := os.WriteFile(path, []byte(content), 0644)
	require.NoError(t, err)
	return path
}
