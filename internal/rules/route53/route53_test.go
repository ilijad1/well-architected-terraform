package route53

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

func TestQueryLogging_Bad(t *testing.T) {
	resources := loadResources(t, "../../../testdata/route53/bad.tf")
	res := findResource(t, resources, "aws_route53_query_log", "bad")
	findings := (&QueryLogging{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "R53-001", findings[0].RuleID)
}

func TestQueryLogging_Good(t *testing.T) {
	resources := loadResources(t, "../../../testdata/route53/good.tf")
	res := findResource(t, resources, "aws_route53_query_log", "good")
	assert.Empty(t, (&QueryLogging{}).Evaluate(res))
}

func TestDNSSEC_Bad(t *testing.T) {
	resources := loadResources(t, "../../../testdata/route53/bad.tf")
	res := findResource(t, resources, "aws_route53_hosted_zone_dnssec", "bad")
	findings := (&DNSSEC{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "R53-002", findings[0].RuleID)
}

func TestDNSSEC_Good(t *testing.T) {
	resources := loadResources(t, "../../../testdata/route53/good.tf")
	res := findResource(t, resources, "aws_route53_hosted_zone_dnssec", "good")
	assert.Empty(t, (&DNSSEC{}).Evaluate(res))
}
