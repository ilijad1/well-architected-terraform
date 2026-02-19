package firehose

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

func TestDeliveryStreamEncryption_NoEncryption(t *testing.T) {
	resources := loadResources(t, "../../../testdata/firehose/bad.tf")
	res := findResource(t, resources, "aws_kinesis_firehose_delivery_stream", "no_encryption")
	findings := (&DeliveryStreamEncryption{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "KDF-001", findings[0].RuleID)
}

func TestDeliveryStreamEncryption_Encrypted(t *testing.T) {
	resources := loadResources(t, "../../../testdata/firehose/good.tf")
	res := findResource(t, resources, "aws_kinesis_firehose_delivery_stream", "encrypted_with_backup")
	findings := (&DeliveryStreamEncryption{}).Evaluate(res)
	assert.Empty(t, findings)
}

func TestS3BackupEnabled_NotEnabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/firehose/bad.tf")
	res := findResource(t, resources, "aws_kinesis_firehose_delivery_stream", "no_backup")
	findings := (&S3BackupEnabled{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "KDF-002", findings[0].RuleID)
}

func TestS3BackupEnabled_Enabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/firehose/good.tf")
	res := findResource(t, resources, "aws_kinesis_firehose_delivery_stream", "encrypted_with_backup")
	findings := (&S3BackupEnabled{}).Evaluate(res)
	assert.Empty(t, findings)
}

func TestS3BackupEnabled_NoExtendedConfig(t *testing.T) {
	// Rule only applies when extended_s3_configuration block exists
	resource := model.TerraformResource{
		Type:       "aws_kinesis_firehose_delivery_stream",
		Name:       "s3_dest",
		Attributes: map[string]interface{}{"destination": "s3"},
		Blocks:     map[string][]model.Block{},
	}
	findings := (&S3BackupEnabled{}).Evaluate(resource)
	assert.Empty(t, findings)
}
