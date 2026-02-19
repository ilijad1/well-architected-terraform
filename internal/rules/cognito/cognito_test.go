package cognito

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

func TestMFA_Bad(t *testing.T) {
	resources := loadResources(t, "../../../testdata/cognito/bad.tf")
	res := findResource(t, resources, "aws_cognito_user_pool", "bad")
	assert.Len(t, (&MFAConfiguration{}).Evaluate(res), 1)
}

func TestUnauthAccess_Bad(t *testing.T) {
	resources := loadResources(t, "../../../testdata/cognito/bad.tf")
	res := findResource(t, resources, "aws_cognito_identity_pool", "bad")
	assert.Len(t, (&NoUnauthAccess{}).Evaluate(res), 1)
}

func TestAllRules_Good(t *testing.T) {
	resources := loadResources(t, "../../../testdata/cognito/good.tf")
	res := findResource(t, resources, "aws_cognito_user_pool", "good")
	assert.Empty(t, (&MFAConfiguration{}).Evaluate(res))
	assert.Empty(t, (&AdvancedSecurity{}).Evaluate(res))
	assert.Empty(t, (&DeletionProtection{}).Evaluate(res))
	assert.Empty(t, (&PasswordPolicy{}).Evaluate(res))
}

func TestUnauthAccess_Good(t *testing.T) {
	resources := loadResources(t, "../../../testdata/cognito/good.tf")
	res := findResource(t, resources, "aws_cognito_identity_pool", "good")
	assert.Empty(t, (&NoUnauthAccess{}).Evaluate(res))
}
