package organizations

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func res(resType, name string, attrs map[string]interface{}) model.TerraformResource {
	return model.TerraformResource{
		Type:       resType,
		Name:       name,
		Attributes: attrs,
		Blocks:     map[string][]model.Block{},
	}
}

// --- ORG-001: SCP Wildcard ---

func TestSCPWildcard_WildcardAllow(t *testing.T) {
	r := &SCPWildcardRule{}
	findings := r.Evaluate(res("aws_organizations_policy", "scp", map[string]interface{}{
		"type":    "SERVICE_CONTROL_POLICY",
		"content": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
	}))
	assert.Len(t, findings, 1)
	assert.Equal(t, "ORG-001", findings[0].RuleID)
}

func TestSCPWildcard_DenyStatement(t *testing.T) {
	r := &SCPWildcardRule{}
	findings := r.Evaluate(res("aws_organizations_policy", "scp", map[string]interface{}{
		"type":    "SERVICE_CONTROL_POLICY",
		"content": `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`,
	}))
	assert.Empty(t, findings)
}

func TestSCPWildcard_ScopedAllow(t *testing.T) {
	r := &SCPWildcardRule{}
	findings := r.Evaluate(res("aws_organizations_policy", "scp", map[string]interface{}{
		"type":    "SERVICE_CONTROL_POLICY",
		"content": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"*"}]}`,
	}))
	assert.Empty(t, findings)
}

func TestSCPWildcard_NonSCPPolicy(t *testing.T) {
	r := &SCPWildcardRule{}
	findings := r.Evaluate(res("aws_organizations_policy", "tag_policy", map[string]interface{}{
		"type":    "TAG_POLICY",
		"content": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
	}))
	assert.Empty(t, findings)
}

// --- ORG-002: SCP Unattached ---

func TestSCPUnattached_NoAttachment(t *testing.T) {
	r := &SCPUnattachedRule{}
	resources := []model.TerraformResource{
		res("aws_organizations_policy", "restrict_regions", map[string]interface{}{
			"type": "SERVICE_CONTROL_POLICY",
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Len(t, findings, 1)
	assert.Equal(t, "ORG-002", findings[0].RuleID)
}

func TestSCPUnattached_WithAttachment(t *testing.T) {
	r := &SCPUnattachedRule{}
	policy := res("aws_organizations_policy", "restrict_regions", map[string]interface{}{
		"type": "SERVICE_CONTROL_POLICY",
		"id":   "p-abc123",
	})
	attachment := res("aws_organizations_policy_attachment", "att", map[string]interface{}{
		"policy_id": "p-abc123",
		"target_id": "ou-root-123",
	})
	findings := r.EvaluateAll([]model.TerraformResource{policy, attachment})
	assert.Empty(t, findings)
}

func TestSCPUnattached_NonSCPIgnored(t *testing.T) {
	r := &SCPUnattachedRule{}
	resources := []model.TerraformResource{
		res("aws_organizations_policy", "tag_policy", map[string]interface{}{
			"type": "TAG_POLICY",
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Empty(t, findings)
}

// --- ORG-003: OU Without SCP ---

func TestOUNoSCP_NoAttachment(t *testing.T) {
	r := &OUNoSCPRule{}
	resources := []model.TerraformResource{
		res("aws_organizations_organizational_unit", "dev", map[string]interface{}{}),
	}
	findings := r.EvaluateAll(resources)
	assert.Len(t, findings, 1)
	assert.Equal(t, "ORG-003", findings[0].RuleID)
}

func TestOUNoSCP_WithAttachment(t *testing.T) {
	r := &OUNoSCPRule{}
	ou := res("aws_organizations_organizational_unit", "dev", map[string]interface{}{
		"id": "ou-dev-123",
	})
	attachment := res("aws_organizations_policy_attachment", "dev_scp", map[string]interface{}{
		"policy_id": "p-abc",
		"target_id": "ou-dev-123",
	})
	findings := r.EvaluateAll([]model.TerraformResource{ou, attachment})
	assert.Empty(t, findings)
}
