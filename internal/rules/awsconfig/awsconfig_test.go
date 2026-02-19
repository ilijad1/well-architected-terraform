package awsconfig

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

func TestConfigRecorder_AllSupported(t *testing.T) {
	resources := loadResources(t, "../../../testdata/awsconfig/good.tf")
	res := findResource(t, resources, "aws_config_configuration_recorder", "main")
	findings := (&ConfigRecorder{}).Evaluate(res)
	assert.Empty(t, findings)
}

func TestConfigRecorder_NotAllSupported(t *testing.T) {
	resources := loadResources(t, "../../../testdata/awsconfig/bad.tf")
	res := findResource(t, resources, "aws_config_configuration_recorder", "partial")
	findings := (&ConfigRecorder{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "CFG-001", findings[0].RuleID)
	assert.Equal(t, model.SeverityHigh, findings[0].Severity)
}

func TestConfigRecorderStatus_Enabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/awsconfig/good.tf")
	res := findResource(t, resources, "aws_config_configuration_recorder_status", "main")
	findings := (&ConfigRecorderStatus{}).Evaluate(res)
	assert.Empty(t, findings)
}

func TestConfigRecorderStatus_Disabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/awsconfig/bad.tf")
	res := findResource(t, resources, "aws_config_configuration_recorder_status", "disabled")
	findings := (&ConfigRecorderStatus{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "CFG-002", findings[0].RuleID)
}

func TestConfigDeliveryChannel_WithBucket(t *testing.T) {
	resources := loadResources(t, "../../../testdata/awsconfig/good.tf")
	res := findResource(t, resources, "aws_config_delivery_channel", "main")
	findings := (&ConfigDeliveryChannel{}).Evaluate(res)
	assert.Empty(t, findings)
}

func TestConfigDeliveryChannel_NoBucket(t *testing.T) {
	resources := loadResources(t, "../../../testdata/awsconfig/bad.tf")
	res := findResource(t, resources, "aws_config_delivery_channel", "no_bucket")
	findings := (&ConfigDeliveryChannel{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "CFG-003", findings[0].RuleID)
}
