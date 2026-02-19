package guardduty

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

func TestDetectorEnabled_Disabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/guardduty/bad.tf")
	res := findResource(t, resources, "aws_guardduty_detector", "bad")
	assert.Len(t, (&DetectorEnabled{}).Evaluate(res), 1)
}

func TestDetectorEnabled_Enabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/guardduty/good.tf")
	res := findResource(t, resources, "aws_guardduty_detector", "good")
	assert.Empty(t, (&DetectorEnabled{}).Evaluate(res))
}
