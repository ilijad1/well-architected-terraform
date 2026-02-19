package iam

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func newRes(resType, name string, attrs map[string]interface{}) model.TerraformResource {
	return model.TerraformResource{
		Type:       resType,
		Name:       name,
		Attributes: attrs,
		Blocks:     map[string][]model.Block{},
	}
}

// --- IAM-008: Access Key ---

func TestAccessKey_AlwaysFlags(t *testing.T) {
	r := &AccessKeyRule{}
	findings := r.Evaluate(newRes("aws_iam_access_key", "user_key", map[string]interface{}{
		"user": "legacy-user",
	}))
	assert.Len(t, findings, 1)
	assert.Equal(t, "IAM-008", findings[0].RuleID)
	assert.Equal(t, model.SeverityHigh, findings[0].Severity)
}

// --- IAM-009: Cross-Account Trust Missing ExternalId ---

func TestRoleTrustExternalID_CrossAccountNoExternalID(t *testing.T) {
	trustPolicy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::999999999999:root"},
			"Action": "sts:AssumeRole"
		}]
	}`
	r := &RoleTrustExternalIDRule{}
	findings := r.Evaluate(newRes("aws_iam_role", "cross_account", map[string]interface{}{
		"assume_role_policy": trustPolicy,
	}))
	assert.Len(t, findings, 1)
	assert.Equal(t, "IAM-009", findings[0].RuleID)
}

func TestRoleTrustExternalID_CrossAccountWithExternalID(t *testing.T) {
	trustPolicy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::999999999999:root"},
			"Action": "sts:AssumeRole",
			"Condition": {
				"StringEquals": {
					"sts:ExternalId": "unique-id-123"
				}
			}
		}]
	}`
	r := &RoleTrustExternalIDRule{}
	findings := r.Evaluate(newRes("aws_iam_role", "cross_account", map[string]interface{}{
		"assume_role_policy": trustPolicy,
	}))
	assert.Empty(t, findings)
}

func TestRoleTrustExternalID_SameServicePrincipal(t *testing.T) {
	trustPolicy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"Service": "lambda.amazonaws.com"},
			"Action": "sts:AssumeRole"
		}]
	}`
	r := &RoleTrustExternalIDRule{}
	findings := r.Evaluate(newRes("aws_iam_role", "lambda_role", map[string]interface{}{
		"assume_role_policy": trustPolicy,
	}))
	assert.Empty(t, findings)
}

// --- IAM-010: PassRole Without Condition ---

func TestPassRoleCondition_NoCondition(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "iam:PassRole",
			"Resource": "*"
		}]
	}`
	r := &PassRoleConditionRule{}
	findings := r.Evaluate(newRes("aws_iam_policy", "pass_role", map[string]interface{}{
		"policy": policy,
	}))
	assert.Len(t, findings, 1)
	assert.Equal(t, "IAM-010", findings[0].RuleID)
}

func TestPassRoleCondition_WithCondition(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "iam:PassRole",
			"Resource": "*",
			"Condition": {
				"StringEquals": {
					"iam:PassedToService": "lambda.amazonaws.com"
				}
			}
		}]
	}`
	r := &PassRoleConditionRule{}
	findings := r.Evaluate(newRes("aws_iam_policy", "pass_role", map[string]interface{}{
		"policy": policy,
	}))
	assert.Empty(t, findings)
}

func TestPassRoleCondition_NoPassRoleAction(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "s3:GetObject",
			"Resource": "*"
		}]
	}`
	r := &PassRoleConditionRule{}
	findings := r.Evaluate(newRes("aws_iam_policy", "safe", map[string]interface{}{
		"policy": policy,
	}))
	assert.Empty(t, findings)
}

// --- IAM-011: Wildcard Trust Policy ---

func TestRoleWildcardTrust_WildcardNoConditions(t *testing.T) {
	trustPolicy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "sts:AssumeRole"
		}]
	}`
	r := &RoleWildcardTrustRule{}
	findings := r.Evaluate(newRes("aws_iam_role", "open_role", map[string]interface{}{
		"assume_role_policy": trustPolicy,
	}))
	assert.Len(t, findings, 1)
	assert.Equal(t, "IAM-011", findings[0].RuleID)
	assert.Equal(t, model.SeverityCritical, findings[0].Severity)
}

func TestRoleWildcardTrust_WildcardWithConditions(t *testing.T) {
	trustPolicy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "sts:AssumeRole",
			"Condition": {
				"StringEquals": {
					"aws:PrincipalOrgID": "o-1234567890"
				}
			}
		}]
	}`
	r := &RoleWildcardTrustRule{}
	findings := r.Evaluate(newRes("aws_iam_role", "org_role", map[string]interface{}{
		"assume_role_policy": trustPolicy,
	}))
	assert.Empty(t, findings)
}

func TestRoleWildcardTrust_SpecificPrincipal(t *testing.T) {
	trustPolicy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
			"Action": "sts:AssumeRole"
		}]
	}`
	r := &RoleWildcardTrustRule{}
	findings := r.Evaluate(newRes("aws_iam_role", "safe_role", map[string]interface{}{
		"assume_role_policy": trustPolicy,
	}))
	assert.Empty(t, findings)
}

// --- IAM-012: Permission Boundary ---

func TestPermissionBoundary_Missing(t *testing.T) {
	r := &PermissionBoundaryRule{}
	findings := r.Evaluate(newRes("aws_iam_role", "no_boundary", map[string]interface{}{
		"name": "unbounded-role",
	}))
	assert.Len(t, findings, 1)
	assert.Equal(t, "IAM-012", findings[0].RuleID)
}

func TestPermissionBoundary_Present(t *testing.T) {
	r := &PermissionBoundaryRule{}
	findings := r.Evaluate(newRes("aws_iam_role", "bounded", map[string]interface{}{
		"name":                 "bounded-role",
		"permissions_boundary": "arn:aws:iam::123456789012:policy/boundary",
	}))
	assert.Empty(t, findings)
}

// --- IAM-013: Admin Attachment (Cross-Resource) ---

func TestCrossAdminAttachment_AdminPolicy(t *testing.T) {
	r := &CrossAdminAttachmentRule{}
	resources := []model.TerraformResource{
		newRes("aws_iam_role_policy_attachment", "admin_att", map[string]interface{}{
			"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Len(t, findings, 1)
	assert.Equal(t, "IAM-013", findings[0].RuleID)
	assert.Equal(t, model.SeverityCritical, findings[0].Severity)
}

func TestCrossAdminAttachment_NonAdminPolicy(t *testing.T) {
	r := &CrossAdminAttachmentRule{}
	resources := []model.TerraformResource{
		newRes("aws_iam_role_policy_attachment", "readonly", map[string]interface{}{
			"policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Empty(t, findings)
}

func TestCrossAdminAttachment_UserAttachment(t *testing.T) {
	r := &CrossAdminAttachmentRule{}
	resources := []model.TerraformResource{
		newRes("aws_iam_user_policy_attachment", "user_admin", map[string]interface{}{
			"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Len(t, findings, 1)
}

// --- IAM-014: Inline Wildcard (Cross-Resource) ---

func TestCrossInlineWildcard_WildcardPolicy(t *testing.T) {
	r := &CrossInlineWildcardRule{}
	resources := []model.TerraformResource{
		newRes("aws_iam_role", "admin_role", map[string]interface{}{
			"name": "admin-role",
		}),
		newRes("aws_iam_role_policy", "inline_admin", map[string]interface{}{
			"role":   "admin-role",
			"policy": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Len(t, findings, 1)
	assert.Equal(t, "IAM-014", findings[0].RuleID)
}

func TestCrossInlineWildcard_ScopedPolicy(t *testing.T) {
	r := &CrossInlineWildcardRule{}
	resources := []model.TerraformResource{
		newRes("aws_iam_role", "scoped_role", map[string]interface{}{
			"name": "scoped-role",
		}),
		newRes("aws_iam_role_policy", "inline_scoped", map[string]interface{}{
			"role":   "scoped-role",
			"policy": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/*"}]}`,
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Empty(t, findings)
}

func TestCrossInlineWildcard_ServiceWildcard(t *testing.T) {
	r := &CrossInlineWildcardRule{}
	resources := []model.TerraformResource{
		newRes("aws_iam_role", "s3_admin", map[string]interface{}{
			"name": "s3-admin-role",
		}),
		newRes("aws_iam_role_policy", "inline_s3_wild", map[string]interface{}{
			"role":   "s3-admin-role",
			"policy": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`,
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Len(t, findings, 1)
}
