package redshift

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

func TestAllRules_Bad(t *testing.T) {
	resources := loadResources(t, "../../../testdata/redshift/bad.tf")
	res := findResource(t, resources, "aws_redshift_cluster", "bad")

	assert.Len(t, (&Encryption{}).Evaluate(res), 1)
	assert.Len(t, (&PublicAccess{}).Evaluate(res), 1)
	assert.Len(t, (&Logging{}).Evaluate(res), 1)
	assert.Len(t, (&EnhancedVPCRouting{}).Evaluate(res), 1)
	assert.Len(t, (&MultiNode{}).Evaluate(res), 1)
}

func TestRequireSSL_Bad(t *testing.T) {
	resources := loadResources(t, "../../../testdata/redshift/bad.tf")
	res := findResource(t, resources, "aws_redshift_parameter_group", "bad")
	assert.Len(t, (&RequireSSL{}).Evaluate(res), 1)
}

func TestAllRules_Good(t *testing.T) {
	resources := loadResources(t, "../../../testdata/redshift/good.tf")
	res := findResource(t, resources, "aws_redshift_cluster", "good")

	assert.Empty(t, (&Encryption{}).Evaluate(res))
	assert.Empty(t, (&PublicAccess{}).Evaluate(res))
	assert.Empty(t, (&Logging{}).Evaluate(res))
	assert.Empty(t, (&EnhancedVPCRouting{}).Evaluate(res))
	assert.Empty(t, (&MultiNode{}).Evaluate(res))
}

func TestRequireSSL_Good(t *testing.T) {
	resources := loadResources(t, "../../../testdata/redshift/good.tf")
	res := findResource(t, resources, "aws_redshift_parameter_group", "good")
	assert.Empty(t, (&RequireSSL{}).Evaluate(res))
}

func TestTags_Missing(t *testing.T) {
	resources := loadResources(t, "../../../testdata/redshift/bad.tf")
	res := findResource(t, resources, "aws_redshift_cluster", "bad")
	assert.Len(t, (&Tags{}).Evaluate(res), 1)
}

func TestTags_Present(t *testing.T) {
	resources := loadResources(t, "../../../testdata/redshift/good.tf")
	res := findResource(t, resources, "aws_redshift_cluster", "good")
	assert.Empty(t, (&Tags{}).Evaluate(res))
}

func TestSnapshotRetention_Missing(t *testing.T) {
	resources := loadResources(t, "../../../testdata/redshift/bad.tf")
	res := findResource(t, resources, "aws_redshift_cluster", "bad")
	assert.Len(t, (&SnapshotRetention{}).Evaluate(res), 1)
}

func TestSnapshotRetention_Configured(t *testing.T) {
	resources := loadResources(t, "../../../testdata/redshift/good.tf")
	res := findResource(t, resources, "aws_redshift_cluster", "good")
	assert.Empty(t, (&SnapshotRetention{}).Evaluate(res))
}
