package dms

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

func TestNotPublic_Public(t *testing.T) {
	resources := loadResources(t, "../../../testdata/dms/bad.tf")
	res := findResource(t, resources, "aws_dms_replication_instance", "bad")
	findings := (&NotPublic{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "DMS-001", findings[0].RuleID)
}

func TestNotPublic_Private(t *testing.T) {
	resources := loadResources(t, "../../../testdata/dms/good.tf")
	res := findResource(t, resources, "aws_dms_replication_instance", "good")
	findings := (&NotPublic{}).Evaluate(res)
	assert.Empty(t, findings)
}

func TestKMSEncryption_Missing(t *testing.T) {
	resources := loadResources(t, "../../../testdata/dms/bad.tf")
	res := findResource(t, resources, "aws_dms_replication_instance", "bad")
	findings := (&KMSEncryption{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "DMS-002", findings[0].RuleID)
}

func TestKMSEncryption_Present(t *testing.T) {
	resources := loadResources(t, "../../../testdata/dms/good.tf")
	res := findResource(t, resources, "aws_dms_replication_instance", "good")
	findings := (&KMSEncryption{}).Evaluate(res)
	assert.Empty(t, findings)
}

func TestAutoMinorVersion_Disabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/dms/bad.tf")
	res := findResource(t, resources, "aws_dms_replication_instance", "bad")
	findings := (&AutoMinorVersion{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "DMS-003", findings[0].RuleID)
}

func TestAutoMinorVersion_Enabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/dms/good.tf")
	res := findResource(t, resources, "aws_dms_replication_instance", "good")
	findings := (&AutoMinorVersion{}).Evaluate(res)
	assert.Empty(t, findings)
}
