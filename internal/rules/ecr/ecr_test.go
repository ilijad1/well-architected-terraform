package ecr

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

func TestScanOnPush_Disabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ecr/bad.tf")
	res := findResource(t, resources, "aws_ecr_repository", "bad")
	findings := (&ScanOnPush{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "ECR-001", findings[0].RuleID)
}

func TestScanOnPush_Enabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ecr/good.tf")
	res := findResource(t, resources, "aws_ecr_repository", "good")
	findings := (&ScanOnPush{}).Evaluate(res)
	assert.Empty(t, findings)
}

func TestImageTagMutability_Mutable(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ecr/bad.tf")
	res := findResource(t, resources, "aws_ecr_repository", "bad")
	findings := (&ImageTagMutability{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "ECR-002", findings[0].RuleID)
}

func TestEncryption_NoKMS(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ecr/bad.tf")
	res := findResource(t, resources, "aws_ecr_repository", "bad")
	findings := (&Encryption{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "ECR-003", findings[0].RuleID)
}

func TestTags_Missing(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ecr/bad.tf")
	res := findResource(t, resources, "aws_ecr_repository", "bad")
	findings := (&Tags{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "ECR-004", findings[0].RuleID)
}

func TestAllRules_Good(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ecr/good.tf")
	res := findResource(t, resources, "aws_ecr_repository", "good")
	assert.Empty(t, (&ScanOnPush{}).Evaluate(res))
	assert.Empty(t, (&ImageTagMutability{}).Evaluate(res))
	assert.Empty(t, (&Encryption{}).Evaluate(res))
	assert.Empty(t, (&Tags{}).Evaluate(res))
}

func TestLifecyclePolicy_Missing(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ecr/bad.tf")
	res := findResource(t, resources, "aws_ecr_lifecycle_policy", "bad")
	findings := (&LifecyclePolicy{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "ECR-005", findings[0].RuleID)
}

func TestLifecyclePolicy_Configured(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ecr/good.tf")
	res := findResource(t, resources, "aws_ecr_lifecycle_policy", "good")
	findings := (&LifecyclePolicy{}).Evaluate(res)
	assert.Empty(t, findings)
}
