package ecs

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

func TestContainerInsights_Disabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ecs/bad.tf")
	res := findResource(t, resources, "aws_ecs_cluster", "bad")
	findings := (&ContainerInsights{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "ECS-001", findings[0].RuleID)
}

func TestContainerInsights_Enabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ecs/good.tf")
	res := findResource(t, resources, "aws_ecs_cluster", "good")
	findings := (&ContainerInsights{}).Evaluate(res)
	assert.Empty(t, findings)
}

func TestNetworkMode_NotAWSVPC(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ecs/bad.tf")
	res := findResource(t, resources, "aws_ecs_task_definition", "bad")
	findings := (&NetworkMode{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "ECS-006", findings[0].RuleID)
}

func TestNetworkMode_AWSVPC(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ecs/good.tf")
	res := findResource(t, resources, "aws_ecs_task_definition", "good")
	findings := (&NetworkMode{}).Evaluate(res)
	assert.Empty(t, findings)
}

func TestResourceLimits_Missing(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ecs/bad.tf")
	res := findResource(t, resources, "aws_ecs_task_definition", "bad")
	findings := (&ResourceLimits{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "ECS-007", findings[0].RuleID)
}

func TestResourceLimits_Set(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ecs/good.tf")
	res := findResource(t, resources, "aws_ecs_task_definition", "good")
	findings := (&ResourceLimits{}).Evaluate(res)
	assert.Empty(t, findings)
}

func TestClusterTags_Missing(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ecs/bad.tf")
	res := findResource(t, resources, "aws_ecs_cluster", "bad")
	findings := (&ClusterTags{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "ECS-008", findings[0].RuleID)
}

func TestClusterTags_Present(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ecs/good.tf")
	res := findResource(t, resources, "aws_ecs_cluster", "good")
	findings := (&ClusterTags{}).Evaluate(res)
	assert.Empty(t, findings)
}

func TestExecuteCommandLogging_Missing(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ecs/bad.tf")
	res := findResource(t, resources, "aws_ecs_cluster", "bad")
	findings := (&ExecuteCommandLogging{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "ECS-009", findings[0].RuleID)
}

func TestExecuteCommandLogging_Configured(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ecs/good.tf")
	res := findResource(t, resources, "aws_ecs_cluster", "good")
	findings := (&ExecuteCommandLogging{}).Evaluate(res)
	assert.Empty(t, findings)
}
