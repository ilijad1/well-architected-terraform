package dax

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

func TestEncryptionAtRest_Bad(t *testing.T) {
	resources := loadResources(t, "../../../testdata/dax/bad.tf")
	res := findResource(t, resources, "aws_dax_cluster", "bad")
	assert.Len(t, (&EncryptionAtRest{}).Evaluate(res), 1)
}

func TestEncryptionAtRest_Good(t *testing.T) {
	resources := loadResources(t, "../../../testdata/dax/good.tf")
	res := findResource(t, resources, "aws_dax_cluster", "good")
	assert.Empty(t, (&EncryptionAtRest{}).Evaluate(res))
}

func TestEndpointEncryption_Bad(t *testing.T) {
	resources := loadResources(t, "../../../testdata/dax/bad.tf")
	res := findResource(t, resources, "aws_dax_cluster", "bad")
	assert.Len(t, (&EndpointEncryption{}).Evaluate(res), 1)
}

func TestEndpointEncryption_Good(t *testing.T) {
	resources := loadResources(t, "../../../testdata/dax/good.tf")
	res := findResource(t, resources, "aws_dax_cluster", "good")
	assert.Empty(t, (&EndpointEncryption{}).Evaluate(res))
}
