package stepfunctions

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

func TestLogging_Disabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/stepfunctions/bad.tf")
	res := findResource(t, resources, "aws_sfn_state_machine", "bad")
	findings := (&Logging{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "SFN-001", findings[0].RuleID)
}

func TestLogging_Enabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/stepfunctions/good.tf")
	res := findResource(t, resources, "aws_sfn_state_machine", "good")
	findings := (&Logging{}).Evaluate(res)
	assert.Empty(t, findings)
}

func TestTracing_Disabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/stepfunctions/bad.tf")
	res := findResource(t, resources, "aws_sfn_state_machine", "bad")
	findings := (&Tracing{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "SFN-002", findings[0].RuleID)
}

func TestTracing_Enabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/stepfunctions/good.tf")
	res := findResource(t, resources, "aws_sfn_state_machine", "good")
	findings := (&Tracing{}).Evaluate(res)
	assert.Empty(t, findings)
}
