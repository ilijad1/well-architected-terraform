package cloudtrail

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ilijad1/well-architected-terraform/internal/model"
	"github.com/ilijad1/well-architected-terraform/internal/parser"
)

func loadResources(t *testing.T, file string) []model.TerraformResource {
	t.Helper()
	p := parser.New()
	resources, err := p.ParseFile(file)
	require.NoError(t, err)
	return resources
}

func findResource(t *testing.T, resources []model.TerraformResource, resType, name string) model.TerraformResource {
	t.Helper()
	for _, r := range resources {
		if r.Type == resType && r.Name == name {
			return r
		}
	}
	t.Fatalf("%s.%s not found", resType, name)
	return model.TerraformResource{}
}

func TestMultiRegion_Disabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/cloudtrail/bad.tf")
	res := findResource(t, resources, "aws_cloudtrail", "bad")
	findings := (&MultiRegion{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "CT-001", findings[0].RuleID)
}

func TestMultiRegion_Enabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/cloudtrail/good.tf")
	res := findResource(t, resources, "aws_cloudtrail", "good")
	findings := (&MultiRegion{}).Evaluate(res)
	assert.Empty(t, findings)
}

func TestKMSEncryption_Missing(t *testing.T) {
	resources := loadResources(t, "../../../testdata/cloudtrail/bad.tf")
	res := findResource(t, resources, "aws_cloudtrail", "bad")
	findings := (&KMSEncryption{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "CT-002", findings[0].RuleID)
}

func TestLogFileValidation_Disabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/cloudtrail/bad.tf")
	res := findResource(t, resources, "aws_cloudtrail", "bad")
	findings := (&LogFileValidation{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "CT-003", findings[0].RuleID)
}

func TestCloudWatchLogs_Missing(t *testing.T) {
	resources := loadResources(t, "../../../testdata/cloudtrail/bad.tf")
	res := findResource(t, resources, "aws_cloudtrail", "bad")
	findings := (&CloudWatchLogs{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "CT-004", findings[0].RuleID)
}

func TestEnableLogging_Disabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/cloudtrail/bad.tf")
	res := findResource(t, resources, "aws_cloudtrail", "disabled")
	findings := (&EnableLogging{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "CT-005", findings[0].RuleID)
}

func TestAllRules_Good(t *testing.T) {
	resources := loadResources(t, "../../../testdata/cloudtrail/good.tf")
	res := findResource(t, resources, "aws_cloudtrail", "good")

	assert.Empty(t, (&MultiRegion{}).Evaluate(res))
	assert.Empty(t, (&KMSEncryption{}).Evaluate(res))
	assert.Empty(t, (&LogFileValidation{}).Evaluate(res))
	assert.Empty(t, (&CloudWatchLogs{}).Evaluate(res))
	assert.Empty(t, (&EnableLogging{}).Evaluate(res))
}

func TestS3DataEvents_Missing(t *testing.T) {
	resources := loadResources(t, "../../../testdata/cloudtrail/bad.tf")
	res := findResource(t, resources, "aws_cloudtrail", "no_s3_events")
	findings := (&S3DataEvents{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "CT-006", findings[0].RuleID)
}

func TestS3DataEvents_Enabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/cloudtrail/good.tf")
	res := findResource(t, resources, "aws_cloudtrail", "good")
	findings := (&S3DataEvents{}).Evaluate(res)
	assert.Empty(t, findings)
}

// --- CT-007: Cross Log Group ---

func makeRes(resType, name string, attrs map[string]interface{}) model.TerraformResource {
	return model.TerraformResource{
		Type:       resType,
		Name:       name,
		Attributes: attrs,
		Blocks:     map[string][]model.Block{},
	}
}

func TestCrossLogGroup_NoTrails(t *testing.T) {
	r := &CrossLogGroupRule{}
	findings := r.EvaluateAll(nil)
	assert.Empty(t, findings)
}

func TestCrossLogGroup_TrailWithMatchingLogGroup(t *testing.T) {
	r := &CrossLogGroupRule{}
	resources := []model.TerraformResource{
		makeRes("aws_cloudtrail", "main", map[string]interface{}{
			"cloud_watch_logs_group_arn": "arn:aws:logs:us-east-1:123456789012:log-group:cloudtrail-logs:*",
		}),
		makeRes("aws_cloudwatch_log_group", "cloudtrail_logs", map[string]interface{}{
			"name": "cloudtrail-logs",
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Empty(t, findings)
}

func TestCrossLogGroup_TrailMissingLogGroup(t *testing.T) {
	r := &CrossLogGroupRule{}
	resources := []model.TerraformResource{
		makeRes("aws_cloudtrail", "main", map[string]interface{}{
			"cloud_watch_logs_group_arn": "arn:aws:logs:us-east-1:123456789012:log-group:cloudtrail-logs:*",
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Len(t, findings, 1)
	assert.Equal(t, "CT-007", findings[0].RuleID)
}

func TestCrossLogGroup_TrailNoARN_NoLogGroupInPlan(t *testing.T) {
	r := &CrossLogGroupRule{}
	resources := []model.TerraformResource{
		makeRes("aws_cloudtrail", "main", map[string]interface{}{}),
	}
	findings := r.EvaluateAll(resources)
	assert.Len(t, findings, 1)
	assert.Equal(t, "CT-007", findings[0].RuleID)
}
