package secretsmanager

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

func TestCMKEncryption_Missing(t *testing.T) {
	resources := loadResources(t, "../../../testdata/secretsmanager/bad.tf")
	res := findResource(t, resources, "aws_secretsmanager_secret", "bad")
	findings := (&CMKEncryption{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "SEC-001", findings[0].RuleID)
}

func TestCMKEncryption_Present(t *testing.T) {
	resources := loadResources(t, "../../../testdata/secretsmanager/good.tf")
	res := findResource(t, resources, "aws_secretsmanager_secret", "good")
	findings := (&CMKEncryption{}).Evaluate(res)
	assert.Empty(t, findings)
}

func TestRotation_Missing(t *testing.T) {
	resources := loadResources(t, "../../../testdata/secretsmanager/bad.tf")
	res := findResource(t, resources, "aws_secretsmanager_secret_rotation", "bad")
	findings := (&Rotation{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "SEC-002", findings[0].RuleID)
}

func TestRotation_Configured(t *testing.T) {
	resources := loadResources(t, "../../../testdata/secretsmanager/good.tf")
	res := findResource(t, resources, "aws_secretsmanager_secret_rotation", "good")
	findings := (&Rotation{}).Evaluate(res)
	assert.Empty(t, findings)
}

func TestSecretTags_Missing(t *testing.T) {
	resources := loadResources(t, "../../../testdata/secretsmanager/bad.tf")
	res := findResource(t, resources, "aws_secretsmanager_secret", "bad")
	findings := (&SecretTags{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "SEC-003", findings[0].RuleID)
}

func TestSecretTags_Present(t *testing.T) {
	resources := loadResources(t, "../../../testdata/secretsmanager/good.tf")
	res := findResource(t, resources, "aws_secretsmanager_secret", "good")
	findings := (&SecretTags{}).Evaluate(res)
	assert.Empty(t, findings)
}

// --- SEC-004: Cross Rotation ---

func makeSecRes(resType, name string, attrs map[string]interface{}) model.TerraformResource {
	return model.TerraformResource{
		Type:       resType,
		Name:       name,
		Attributes: attrs,
		Blocks:     map[string][]model.Block{},
	}
}

func TestCrossRotation_Missing(t *testing.T) {
	r := &CrossRotationRule{}
	resources := []model.TerraformResource{
		makeSecRes("aws_secretsmanager_secret", "db_password", map[string]interface{}{
			"name": "db-password",
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Len(t, findings, 1)
	assert.Equal(t, "SEC-004", findings[0].RuleID)
	assert.Equal(t, model.SeverityHigh, findings[0].Severity)
}

func TestCrossRotation_Present(t *testing.T) {
	r := &CrossRotationRule{}
	resources := []model.TerraformResource{
		makeSecRes("aws_secretsmanager_secret", "db_password", map[string]interface{}{
			"name": "db-password",
		}),
		makeSecRes("aws_secretsmanager_secret_rotation", "db_rotation", map[string]interface{}{
			"secret_id": "db-password",
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Empty(t, findings)
}

func TestCrossRotation_MultipleSecrets_OneUncovered(t *testing.T) {
	r := &CrossRotationRule{}
	resources := []model.TerraformResource{
		makeSecRes("aws_secretsmanager_secret", "s1", map[string]interface{}{"name": "secret-1"}),
		makeSecRes("aws_secretsmanager_secret", "s2", map[string]interface{}{"name": "secret-2"}),
		makeSecRes("aws_secretsmanager_secret_rotation", "r1", map[string]interface{}{"secret_id": "secret-1"}),
	}
	findings := r.EvaluateAll(resources)
	assert.Len(t, findings, 1)
	assert.Contains(t, findings[0].Resource, "s2")
}

func TestCrossRotation_NoSecrets(t *testing.T) {
	r := &CrossRotationRule{}
	findings := r.EvaluateAll(nil)
	assert.Empty(t, findings)
}
