package elb

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

// --- ELB-007: Cross WAF ---

func TestCrossWAF_ALBNoWAF(t *testing.T) {
	r := &CrossWAFRule{}
	resources := []model.TerraformResource{
		newRes("aws_lb", "web", map[string]interface{}{
			"load_balancer_type": "application",
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Len(t, findings, 1)
	assert.Equal(t, "ELB-007", findings[0].RuleID)
}

func TestCrossWAF_ALBWithWAF(t *testing.T) {
	r := &CrossWAFRule{}
	resources := []model.TerraformResource{
		newRes("aws_lb", "web", map[string]interface{}{
			"load_balancer_type": "application",
			"arn":                "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/web/abc123",
		}),
		newRes("aws_wafv2_web_acl_association", "web_waf", map[string]interface{}{
			"resource_arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/web/abc123",
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Empty(t, findings)
}

func TestCrossWAF_NLBSkipped(t *testing.T) {
	r := &CrossWAFRule{}
	resources := []model.TerraformResource{
		newRes("aws_lb", "internal", map[string]interface{}{
			"load_balancer_type": "network",
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Empty(t, findings)
}

func TestCrossWAF_DefaultTypeIsApplication(t *testing.T) {
	r := &CrossWAFRule{}
	resources := []model.TerraformResource{
		newRes("aws_lb", "web", map[string]interface{}{}), // default type is "application"
	}
	findings := r.EvaluateAll(resources)
	assert.Len(t, findings, 1)
}

func TestCrossWAF_ALBResource(t *testing.T) {
	r := &CrossWAFRule{}
	resources := []model.TerraformResource{
		newRes("aws_alb", "legacy", map[string]interface{}{}),
	}
	findings := r.EvaluateAll(resources)
	assert.Len(t, findings, 1)
}
