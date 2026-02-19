package inspector

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

func TestInspectorEnabled_WithTypes(t *testing.T) {
	resources := loadResources(t, "../../../testdata/inspector/good.tf")
	res := findResource(t, resources, "aws_inspector2_enabler", "main")
	findings := (&InspectorEnabled{}).Evaluate(res)
	assert.Empty(t, findings)
}

func TestInspectorEnabled_NoTypes(t *testing.T) {
	resources := loadResources(t, "../../../testdata/inspector/bad.tf")
	res := findResource(t, resources, "aws_inspector2_enabler", "no_types")
	findings := (&InspectorEnabled{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "INS-001", findings[0].RuleID)
	assert.Equal(t, model.SeverityMedium, findings[0].Severity)
}
