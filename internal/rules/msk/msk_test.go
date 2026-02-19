package msk

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
	resources := loadResources(t, "../../../testdata/msk/bad.tf")
	res := findResource(t, resources, "aws_msk_cluster", "bad")
	assert.Len(t, (&EncryptionInTransit{}).Evaluate(res), 1)
	assert.Len(t, (&LoggingInfo{}).Evaluate(res), 1)
	assert.Len(t, (&EnhancedMonitoring{}).Evaluate(res), 1)
}

func TestAllRules_Good(t *testing.T) {
	resources := loadResources(t, "../../../testdata/msk/good.tf")
	res := findResource(t, resources, "aws_msk_cluster", "good")
	assert.Empty(t, (&EncryptionInTransit{}).Evaluate(res))
	assert.Empty(t, (&NoPublicAccess{}).Evaluate(res))
	assert.Empty(t, (&LoggingInfo{}).Evaluate(res))
	assert.Empty(t, (&EnhancedMonitoring{}).Evaluate(res))
}
