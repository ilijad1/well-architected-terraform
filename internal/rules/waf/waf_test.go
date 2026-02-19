package waf

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

func TestRulesPresent_Bad(t *testing.T) {
	resources := loadResources(t, "../../../testdata/waf/bad.tf")
	res := findResource(t, resources, "aws_wafv2_web_acl", "bad")
	assert.Len(t, (&RulesPresent{}).Evaluate(res), 1)
	assert.Len(t, (&DefaultBlock{}).Evaluate(res), 1)
}

func TestAllRules_Good(t *testing.T) {
	resources := loadResources(t, "../../../testdata/waf/good.tf")
	res := findResource(t, resources, "aws_wafv2_web_acl", "good")
	assert.Empty(t, (&RulesPresent{}).Evaluate(res))
	assert.Empty(t, (&DefaultBlock{}).Evaluate(res))
}

func TestRateBasedRule_Missing(t *testing.T) {
	resources := loadResources(t, "../../../testdata/waf/bad.tf")
	res := findResource(t, resources, "aws_wafv2_web_acl", "bad")
	findings := (&RateBasedRule{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "WAF-004", findings[0].RuleID)
	assert.Equal(t, model.SeverityMedium, findings[0].Severity)
}

func TestRateBasedRule_Present(t *testing.T) {
	resources := loadResources(t, "../../../testdata/waf/good.tf")
	res := findResource(t, resources, "aws_wafv2_web_acl", "good")
	findings := (&RateBasedRule{}).Evaluate(res)
	assert.Empty(t, findings)
}
