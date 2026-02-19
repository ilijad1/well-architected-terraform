package workspaces

import (
	"testing"

	"github.com/ilijad1/well-architected-terraform/internal/model"
	"github.com/ilijad1/well-architected-terraform/internal/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// VolumeEncryption Tests

func TestVolumeEncryption_Bad(t *testing.T) {
	resources := loadResources(t, "../../../testdata/workspaces/bad.tf")
	res := findResource(t, resources, "aws_workspaces_workspace", "bad")
	rule := &VolumeEncryption{}
	findings := rule.Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "WS-001", findings[0].RuleID)
}

func TestVolumeEncryption_Good(t *testing.T) {
	resources := loadResources(t, "../../../testdata/workspaces/good.tf")
	res := findResource(t, resources, "aws_workspaces_workspace", "good")
	rule := &VolumeEncryption{}
	findings := rule.Evaluate(res)
	assert.Len(t, findings, 0)
}

// CMKEncryption Tests

func TestCMKEncryption_Bad(t *testing.T) {
	resources := loadResources(t, "../../../testdata/workspaces/bad.tf")
	res := findResource(t, resources, "aws_workspaces_workspace", "bad")
	rule := &CMKEncryption{}
	findings := rule.Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "WS-002", findings[0].RuleID)
}

func TestCMKEncryption_Good(t *testing.T) {
	resources := loadResources(t, "../../../testdata/workspaces/good.tf")
	res := findResource(t, resources, "aws_workspaces_workspace", "good")
	rule := &CMKEncryption{}
	findings := rule.Evaluate(res)
	assert.Len(t, findings, 0)
}
