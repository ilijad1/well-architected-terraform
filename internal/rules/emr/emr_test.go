package emr

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

func TestKerberosAuth_Bad(t *testing.T) {
	resources := loadResources(t, "../../../testdata/emr/bad.tf")
	res := findResource(t, resources, "aws_emr_cluster", "bad")
	findings := (&KerberosAuth{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "EMR-001", findings[0].RuleID)
}

func TestKerberosAuth_Good(t *testing.T) {
	resources := loadResources(t, "../../../testdata/emr/good.tf")
	res := findResource(t, resources, "aws_emr_cluster", "good")
	assert.Empty(t, (&KerberosAuth{}).Evaluate(res))
}

func TestSubnetPlacement_Bad(t *testing.T) {
	resources := loadResources(t, "../../../testdata/emr/bad.tf")
	res := findResource(t, resources, "aws_emr_cluster", "bad")
	findings := (&SubnetPlacement{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "EMR-002", findings[0].RuleID)
}

func TestSubnetPlacement_Good(t *testing.T) {
	resources := loadResources(t, "../../../testdata/emr/good.tf")
	res := findResource(t, resources, "aws_emr_cluster", "good")
	assert.Empty(t, (&SubnetPlacement{}).Evaluate(res))
}

func TestLogURI_Bad(t *testing.T) {
	resources := loadResources(t, "../../../testdata/emr/bad.tf")
	res := findResource(t, resources, "aws_emr_cluster", "bad")
	findings := (&LogURI{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "EMR-003", findings[0].RuleID)
}

func TestLogURI_Good(t *testing.T) {
	resources := loadResources(t, "../../../testdata/emr/good.tf")
	res := findResource(t, resources, "aws_emr_cluster", "good")
	assert.Empty(t, (&LogURI{}).Evaluate(res))
}

func TestSecurityConfig_Bad(t *testing.T) {
	resources := loadResources(t, "../../../testdata/emr/bad.tf")
	res := findResource(t, resources, "aws_emr_cluster", "bad")
	findings := (&SecurityConfig{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "EMR-004", findings[0].RuleID)
}

func TestSecurityConfig_Good(t *testing.T) {
	resources := loadResources(t, "../../../testdata/emr/good.tf")
	res := findResource(t, resources, "aws_emr_cluster", "good")
	assert.Empty(t, (&SecurityConfig{}).Evaluate(res))
}
