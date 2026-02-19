package codebuild

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

func TestArtifactEncryption_Bad(t *testing.T) {
	resources := loadResources(t, "../../../testdata/codebuild/bad.tf")
	res := findResource(t, resources, "aws_codebuild_project", "bad")
	assert.Len(t, (&ArtifactEncryption{}).Evaluate(res), 1)
}

func TestLogsConfig_Bad(t *testing.T) {
	resources := loadResources(t, "../../../testdata/codebuild/bad.tf")
	res := findResource(t, resources, "aws_codebuild_project", "bad")
	assert.Len(t, (&LogsConfig{}).Evaluate(res), 1)
}

func TestPrivilegedMode_Bad(t *testing.T) {
	resources := loadResources(t, "../../../testdata/codebuild/bad.tf")
	res := findResource(t, resources, "aws_codebuild_project", "bad")
	assert.Len(t, (&NoPrivilegedMode{}).Evaluate(res), 1)
}

func TestAllRules_Good(t *testing.T) {
	resources := loadResources(t, "../../../testdata/codebuild/good.tf")
	res := findResource(t, resources, "aws_codebuild_project", "good")
	assert.Empty(t, (&ArtifactEncryption{}).Evaluate(res))
	assert.Empty(t, (&LogsConfig{}).Evaluate(res))
	assert.Empty(t, (&NoPrivilegedMode{}).Evaluate(res))
}

func TestVPCConfig_Missing(t *testing.T) {
	resources := loadResources(t, "../../../testdata/codebuild/bad.tf")
	res := findResource(t, resources, "aws_codebuild_project", "bad")
	findings := (&VPCConfig{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "CB-005", findings[0].RuleID)
}

func TestVPCConfig_Configured(t *testing.T) {
	resources := loadResources(t, "../../../testdata/codebuild/good.tf")
	res := findResource(t, resources, "aws_codebuild_project", "good")
	findings := (&VPCConfig{}).Evaluate(res)
	assert.Empty(t, findings)
}
