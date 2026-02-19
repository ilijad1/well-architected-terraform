package glue

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

func TestSecurityConfigEncryption_Bad(t *testing.T) {
	resources := loadResources(t, "../../../testdata/glue/bad.tf")
	res := findResource(t, resources, "aws_glue_security_configuration", "bad")
	assert.Len(t, (&SecurityConfigEncryption{}).Evaluate(res), 1)
}

func TestSecurityConfigEncryption_Good(t *testing.T) {
	resources := loadResources(t, "../../../testdata/glue/good.tf")
	res := findResource(t, resources, "aws_glue_security_configuration", "good")
	assert.Empty(t, (&SecurityConfigEncryption{}).Evaluate(res))
}

func TestCatalogEncryption_Bad(t *testing.T) {
	resources := loadResources(t, "../../../testdata/glue/bad.tf")
	res := findResource(t, resources, "aws_glue_data_catalog_encryption_settings", "bad")
	assert.Len(t, (&CatalogEncryption{}).Evaluate(res), 1)
}

func TestCatalogEncryption_Good(t *testing.T) {
	resources := loadResources(t, "../../../testdata/glue/good.tf")
	res := findResource(t, resources, "aws_glue_data_catalog_encryption_settings", "good")
	assert.Empty(t, (&CatalogEncryption{}).Evaluate(res))
}

func TestConnectionPasswordEncryption_Bad(t *testing.T) {
	resources := loadResources(t, "../../../testdata/glue/bad.tf")
	res := findResource(t, resources, "aws_glue_data_catalog_encryption_settings", "bad")
	assert.Len(t, (&ConnectionPasswordEncryption{}).Evaluate(res), 1)
}

func TestConnectionPasswordEncryption_Good(t *testing.T) {
	resources := loadResources(t, "../../../testdata/glue/good.tf")
	res := findResource(t, resources, "aws_glue_data_catalog_encryption_settings", "good")
	assert.Empty(t, (&ConnectionPasswordEncryption{}).Evaluate(res))
}
