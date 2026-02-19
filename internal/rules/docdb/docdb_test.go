package docdb

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

func TestAllClusterRules_Bad(t *testing.T) {
	resources := loadResources(t, "../../../testdata/docdb/bad.tf")
	res := findResource(t, resources, "aws_docdb_cluster", "bad")
	assert.Len(t, (&Encryption{}).Evaluate(res), 1)
	assert.Len(t, (&AuditLogs{}).Evaluate(res), 1)
	assert.Len(t, (&DeletionProtection{}).Evaluate(res), 1)
	assert.Len(t, (&BackupRetention{}).Evaluate(res), 1)
}

func TestTLS_Bad(t *testing.T) {
	resources := loadResources(t, "../../../testdata/docdb/bad.tf")
	res := findResource(t, resources, "aws_docdb_cluster_parameter_group", "bad")
	assert.Len(t, (&TLSEnabled{}).Evaluate(res), 1)
}

func TestAllClusterRules_Good(t *testing.T) {
	resources := loadResources(t, "../../../testdata/docdb/good.tf")
	res := findResource(t, resources, "aws_docdb_cluster", "good")
	assert.Empty(t, (&Encryption{}).Evaluate(res))
	assert.Empty(t, (&AuditLogs{}).Evaluate(res))
	assert.Empty(t, (&DeletionProtection{}).Evaluate(res))
	assert.Empty(t, (&BackupRetention{}).Evaluate(res))
}

func TestTLS_Good(t *testing.T) {
	resources := loadResources(t, "../../../testdata/docdb/good.tf")
	res := findResource(t, resources, "aws_docdb_cluster_parameter_group", "good")
	assert.Empty(t, (&TLSEnabled{}).Evaluate(res))
}
