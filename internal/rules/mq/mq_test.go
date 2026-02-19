package mq

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
	resources := loadResources(t, "../../../testdata/mq/bad.tf")
	res := findResource(t, resources, "aws_mq_broker", "bad")
	assert.Len(t, (&Logging{}).Evaluate(res), 1)
	assert.Len(t, (&NotPublic{}).Evaluate(res), 1)
	assert.Len(t, (&AutoMinorVersion{}).Evaluate(res), 1)
	assert.Len(t, (&CMKEncryption{}).Evaluate(res), 1)
}

func TestAllRules_Good(t *testing.T) {
	resources := loadResources(t, "../../../testdata/mq/good.tf")
	res := findResource(t, resources, "aws_mq_broker", "good")
	assert.Empty(t, (&Logging{}).Evaluate(res))
	assert.Empty(t, (&NotPublic{}).Evaluate(res))
	assert.Empty(t, (&AutoMinorVersion{}).Evaluate(res))
	assert.Empty(t, (&CMKEncryption{}).Evaluate(res))
}
