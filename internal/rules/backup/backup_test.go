package backup

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

func TestVaultEncryption_Bad(t *testing.T) {
	resources := loadResources(t, "../../../testdata/backup/bad.tf")
	res := findResource(t, resources, "aws_backup_vault", "bad")
	findings := (&VaultEncryption{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "BKP-001", findings[0].RuleID)
}

func TestVaultEncryption_Good(t *testing.T) {
	resources := loadResources(t, "../../../testdata/backup/good.tf")
	res := findResource(t, resources, "aws_backup_vault", "good")
	assert.Empty(t, (&VaultEncryption{}).Evaluate(res))
}

func TestPlanLifecycle_Bad(t *testing.T) {
	resources := loadResources(t, "../../../testdata/backup/bad.tf")
	res := findResource(t, resources, "aws_backup_plan", "bad")
	findings := (&PlanLifecycle{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "BKP-002", findings[0].RuleID)
}

func TestPlanLifecycle_Good(t *testing.T) {
	resources := loadResources(t, "../../../testdata/backup/good.tf")
	res := findResource(t, resources, "aws_backup_plan", "good")
	assert.Empty(t, (&PlanLifecycle{}).Evaluate(res))
}
