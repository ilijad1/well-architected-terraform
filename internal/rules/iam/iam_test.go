package iam

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

func TestWildcardActions_Wildcard(t *testing.T) {
	p := parser.New()
	resources, err := p.ParseFile("../../../testdata/iam/bad.tf")
	require.NoError(t, err)

	rule := &WildcardActions{}
	var totalFindings []model.Finding
	for _, r := range resources {
		totalFindings = append(totalFindings, rule.Evaluate(r)...)
	}

	assert.GreaterOrEqual(t, len(totalFindings), 2)
	for _, f := range totalFindings {
		assert.Equal(t, "IAM-001", f.RuleID)
		assert.Equal(t, model.SeverityHigh, f.Severity)
	}
}

func TestWildcardActions_Specific(t *testing.T) {
	p := parser.New()
	resources, err := p.ParseFile("../../../testdata/iam/good.tf")
	require.NoError(t, err)

	rule := &WildcardActions{}
	for _, r := range resources {
		findings := rule.Evaluate(r)
		assert.Empty(t, findings)
	}
}

func TestPasswordLength_Short(t *testing.T) {
	resources := loadResources(t, "../../../testdata/iam/bad.tf")
	res := findResource(t, resources, "aws_iam_account_password_policy", "weak")

	rule := &PasswordLength{}
	findings := rule.Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "IAM-002", findings[0].RuleID)
}

func TestPasswordLength_Long(t *testing.T) {
	resources := loadResources(t, "../../../testdata/iam/good.tf")
	res := findResource(t, resources, "aws_iam_account_password_policy", "strict")

	rule := &PasswordLength{}
	findings := rule.Evaluate(res)
	assert.Empty(t, findings)
}

func TestPasswordReuse_Low(t *testing.T) {
	resources := loadResources(t, "../../../testdata/iam/bad.tf")
	res := findResource(t, resources, "aws_iam_account_password_policy", "weak")

	rule := &PasswordReuse{}
	findings := rule.Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "IAM-003", findings[0].RuleID)
}

func TestPasswordReuse_High(t *testing.T) {
	resources := loadResources(t, "../../../testdata/iam/good.tf")
	res := findResource(t, resources, "aws_iam_account_password_policy", "strict")

	rule := &PasswordReuse{}
	findings := rule.Evaluate(res)
	assert.Empty(t, findings)
}

func TestUserPolicy_Exists(t *testing.T) {
	resources := loadResources(t, "../../../testdata/iam/bad.tf")
	res := findResource(t, resources, "aws_iam_user_policy", "inline")

	rule := &UserPolicy{}
	findings := rule.Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "IAM-004", findings[0].RuleID)
}

func TestRoleMaxSession_Long(t *testing.T) {
	resources := loadResources(t, "../../../testdata/iam/bad.tf")
	res := findResource(t, resources, "aws_iam_role", "long_session")

	rule := &RoleMaxSession{}
	findings := rule.Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "IAM-005", findings[0].RuleID)
}

func TestRoleMaxSession_Short(t *testing.T) {
	resources := loadResources(t, "../../../testdata/iam/good.tf")
	res := findResource(t, resources, "aws_iam_role", "short_session")

	rule := &RoleMaxSession{}
	findings := rule.Evaluate(res)
	assert.Empty(t, findings)
}

func TestNoFullAdmin_FullAdminPolicy(t *testing.T) {
	resources := loadResources(t, "../../../testdata/iam/bad.tf")
	res := findResource(t, resources, "data.aws_iam_policy_document", "full_admin")
	findings := (&NoFullAdmin{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "IAM-006", findings[0].RuleID)
	assert.Equal(t, model.SeverityCritical, findings[0].Severity)
}

func TestNoFullAdmin_ScopedPolicy(t *testing.T) {
	resources := loadResources(t, "../../../testdata/iam/good.tf")
	res := findResource(t, resources, "data.aws_iam_policy_document", "scoped_policy")
	findings := (&NoFullAdmin{}).Evaluate(res)
	assert.Empty(t, findings)
}

func TestUserGroupMembership_StandaloneUser(t *testing.T) {
	resources := loadResources(t, "../../../testdata/iam/bad.tf")
	res := findResource(t, resources, "aws_iam_user", "standalone")
	findings := (&UserGroupMembership{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "IAM-007", findings[0].RuleID)
}
