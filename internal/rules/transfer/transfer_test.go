package transfer

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

// NoFTP Tests

func TestNoFTP_Bad(t *testing.T) {
	resources := loadResources(t, "../../../testdata/transfer/bad.tf")
	res := findResource(t, resources, "aws_transfer_server", "bad")
	rule := &NoFTP{}
	findings := rule.Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "TFR-001", findings[0].RuleID)
}

func TestNoFTP_Good(t *testing.T) {
	resources := loadResources(t, "../../../testdata/transfer/good.tf")
	res := findResource(t, resources, "aws_transfer_server", "good")
	rule := &NoFTP{}
	findings := rule.Evaluate(res)
	assert.Len(t, findings, 0)
}

// LoggingRole Tests

func TestLoggingRole_Bad(t *testing.T) {
	resources := loadResources(t, "../../../testdata/transfer/bad.tf")
	res := findResource(t, resources, "aws_transfer_server", "bad")
	rule := &LoggingRole{}
	findings := rule.Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "TFR-002", findings[0].RuleID)
}

func TestLoggingRole_Good(t *testing.T) {
	resources := loadResources(t, "../../../testdata/transfer/good.tf")
	res := findResource(t, resources, "aws_transfer_server", "good")
	rule := &LoggingRole{}
	findings := rule.Evaluate(res)
	assert.Len(t, findings, 0)
}
