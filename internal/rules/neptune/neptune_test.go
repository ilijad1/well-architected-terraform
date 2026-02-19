package neptune

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

func TestAllRules_Bad(t *testing.T) {
	resources := loadResources(t, "../../../testdata/neptune/bad.tf")
	res := findResource(t, resources, "aws_neptune_cluster", "bad")
	assert.Len(t, (&Encryption{}).Evaluate(res), 1)
	assert.Len(t, (&AuditLogs{}).Evaluate(res), 1)
	assert.Len(t, (&DeletionProtection{}).Evaluate(res), 1)
	assert.Len(t, (&IAMAuth{}).Evaluate(res), 1)
	assert.Len(t, (&BackupRetention{}).Evaluate(res), 1)
	assert.Len(t, (&CopyTagsToSnapshot{}).Evaluate(res), 1)
}

func TestAllRules_Good(t *testing.T) {
	resources := loadResources(t, "../../../testdata/neptune/good.tf")
	res := findResource(t, resources, "aws_neptune_cluster", "good")
	assert.Empty(t, (&Encryption{}).Evaluate(res))
	assert.Empty(t, (&AuditLogs{}).Evaluate(res))
	assert.Empty(t, (&DeletionProtection{}).Evaluate(res))
	assert.Empty(t, (&IAMAuth{}).Evaluate(res))
	assert.Empty(t, (&BackupRetention{}).Evaluate(res))
	assert.Empty(t, (&CopyTagsToSnapshot{}).Evaluate(res))
}
