package efs

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

func TestEncryption_Disabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/efs/bad.tf")
	res := findResource(t, resources, "aws_efs_file_system", "bad")
	findings := (&Encryption{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "EFS-001", findings[0].RuleID)
}

func TestEncryption_Enabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/efs/good.tf")
	res := findResource(t, resources, "aws_efs_file_system", "good")
	findings := (&Encryption{}).Evaluate(res)
	assert.Empty(t, findings)
}

func TestBackupPolicy_Disabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/efs/bad.tf")
	res := findResource(t, resources, "aws_efs_backup_policy", "bad")
	findings := (&BackupPolicy{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "EFS-002", findings[0].RuleID)
}

func TestBackupPolicy_Enabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/efs/good.tf")
	res := findResource(t, resources, "aws_efs_backup_policy", "good")
	findings := (&BackupPolicy{}).Evaluate(res)
	assert.Empty(t, findings)
}

func TestTags_Missing(t *testing.T) {
	resources := loadResources(t, "../../../testdata/efs/bad.tf")
	res := findResource(t, resources, "aws_efs_file_system", "bad")
	findings := (&Tags{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "EFS-003", findings[0].RuleID)
}

func TestTags_Present(t *testing.T) {
	resources := loadResources(t, "../../../testdata/efs/good.tf")
	res := findResource(t, resources, "aws_efs_file_system", "good")
	findings := (&Tags{}).Evaluate(res)
	assert.Empty(t, findings)
}
