package athena

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

func TestResultEncryption_Bad(t *testing.T) {
	resources := loadResources(t, "../../../testdata/athena/bad.tf")
	res := findResource(t, resources, "aws_athena_workgroup", "bad")
	assert.Len(t, (&ResultEncryption{}).Evaluate(res), 1)
}

func TestResultEncryption_Good(t *testing.T) {
	resources := loadResources(t, "../../../testdata/athena/good.tf")
	res := findResource(t, resources, "aws_athena_workgroup", "good")
	assert.Empty(t, (&ResultEncryption{}).Evaluate(res))
}

func TestEnforceConfig_Bad(t *testing.T) {
	resources := loadResources(t, "../../../testdata/athena/bad.tf")
	res := findResource(t, resources, "aws_athena_workgroup", "bad")
	assert.Len(t, (&EnforceConfig{}).Evaluate(res), 1)
}

func TestEnforceConfig_Good(t *testing.T) {
	resources := loadResources(t, "../../../testdata/athena/good.tf")
	res := findResource(t, resources, "aws_athena_workgroup", "good")
	assert.Empty(t, (&EnforceConfig{}).Evaluate(res))
}
