package opensearch

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
	resources := loadResources(t, "../../../testdata/opensearch/bad.tf")
	res := findResource(t, resources, "aws_opensearch_domain", "bad")

	assert.Len(t, (&EncryptAtRest{}).Evaluate(res), 1)
	assert.Len(t, (&NodeToNode{}).Evaluate(res), 1)
	assert.Len(t, (&EnforceHTTPS{}).Evaluate(res), 1)
	assert.Len(t, (&VPCEndpoint{}).Evaluate(res), 1)
	assert.Len(t, (&AuditLogs{}).Evaluate(res), 1)
	assert.Len(t, (&AdvancedSecurity{}).Evaluate(res), 1)
	assert.Len(t, (&TLSPolicy{}).Evaluate(res), 1)
}

func TestAllRules_Good(t *testing.T) {
	resources := loadResources(t, "../../../testdata/opensearch/good.tf")
	res := findResource(t, resources, "aws_opensearch_domain", "good")

	assert.Empty(t, (&EncryptAtRest{}).Evaluate(res))
	assert.Empty(t, (&NodeToNode{}).Evaluate(res))
	assert.Empty(t, (&EnforceHTTPS{}).Evaluate(res))
	assert.Empty(t, (&VPCEndpoint{}).Evaluate(res))
	assert.Empty(t, (&AuditLogs{}).Evaluate(res))
	assert.Empty(t, (&AdvancedSecurity{}).Evaluate(res))
	assert.Empty(t, (&TLSPolicy{}).Evaluate(res))
}

func TestTags_Missing(t *testing.T) {
	resources := loadResources(t, "../../../testdata/opensearch/bad.tf")
	res := findResource(t, resources, "aws_opensearch_domain", "bad")
	assert.Len(t, (&Tags{}).Evaluate(res), 1)
}

func TestTags_Present(t *testing.T) {
	resources := loadResources(t, "../../../testdata/opensearch/good.tf")
	res := findResource(t, resources, "aws_opensearch_domain", "good")
	assert.Empty(t, (&Tags{}).Evaluate(res))
}
