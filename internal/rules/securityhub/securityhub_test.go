package securityhub

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

func TestAccountEnabled_Present(t *testing.T) {
	resources := loadResources(t, "../../../testdata/securityhub/good.tf")
	for _, r := range resources {
		if r.Type == "aws_securityhub_account" {
			findings := (&AccountEnabled{}).Evaluate(r)
			assert.Empty(t, findings)
			return
		}
	}
	t.Fatal("aws_securityhub_account not found")
}

func TestAccountEnabled_ResourceType(t *testing.T) {
	meta := (&AccountEnabled{}).Metadata()
	assert.Equal(t, "SHB-001", meta.ID)
	assert.Contains(t, meta.ResourceTypes, "aws_securityhub_account")
	assert.Equal(t, model.SeverityHigh, meta.Severity)
}
