package eventbridge

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

func TestRuleEnabled_Disabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/eventbridge/bad.tf")
	res := findResource(t, resources, "aws_cloudwatch_event_rule", "disabled")
	findings := (&RuleEnabled{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "EB-001", findings[0].RuleID)
	assert.Equal(t, model.SeverityMedium, findings[0].Severity)
}

func TestRuleEnabled_Enabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/eventbridge/good.tf")
	res := findResource(t, resources, "aws_cloudwatch_event_rule", "enabled_custom_bus")
	findings := (&RuleEnabled{}).Evaluate(res)
	assert.Empty(t, findings)
}

func TestCrossAccountEventBus_DefaultBus(t *testing.T) {
	resources := loadResources(t, "../../../testdata/eventbridge/bad.tf")
	res := findResource(t, resources, "aws_cloudwatch_event_rule", "default_bus")
	findings := (&CrossAccountEventBus{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "EB-002", findings[0].RuleID)
}

func TestCrossAccountEventBus_CustomBus(t *testing.T) {
	resources := loadResources(t, "../../../testdata/eventbridge/good.tf")
	res := findResource(t, resources, "aws_cloudwatch_event_rule", "enabled_custom_bus")
	findings := (&CrossAccountEventBus{}).Evaluate(res)
	assert.Empty(t, findings)
}
