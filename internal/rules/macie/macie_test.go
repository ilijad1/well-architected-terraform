package macie

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

func TestAccountEnabled_Enabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/macie/good.tf")
	res := findResource(t, resources, "aws_macie2_account", "main")
	findings := (&AccountEnabled{}).Evaluate(res)
	assert.Empty(t, findings)
}

func TestAccountEnabled_Paused(t *testing.T) {
	resources := loadResources(t, "../../../testdata/macie/bad.tf")
	res := findResource(t, resources, "aws_macie2_account", "disabled")
	findings := (&AccountEnabled{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "MAC-001", findings[0].RuleID)
	assert.Equal(t, model.SeverityMedium, findings[0].Severity)
}
