package vpc

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

// --- VPC-007: Cross Flow Log ---

func TestCrossFlowLog_Missing(t *testing.T) {
	r := &CrossFlowLogRule{}
	resources := []model.TerraformResource{
		newRes("aws_vpc", "main", map[string]interface{}{}),
	}
	findings := r.EvaluateAll(resources)
	assert.Len(t, findings, 1)
	assert.Equal(t, "VPC-007", findings[0].RuleID)
}

func TestCrossFlowLog_Present(t *testing.T) {
	r := &CrossFlowLogRule{}
	resources := []model.TerraformResource{
		newRes("aws_vpc", "main", map[string]interface{}{
			"id": "vpc-abc123",
		}),
		newRes("aws_flow_log", "main_flow", map[string]interface{}{
			"vpc_id": "vpc-abc123",
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Empty(t, findings)
}

func TestCrossFlowLog_MultipleVPCs(t *testing.T) {
	r := &CrossFlowLogRule{}
	resources := []model.TerraformResource{
		newRes("aws_vpc", "prod", map[string]interface{}{"id": "vpc-prod"}),
		newRes("aws_vpc", "dev", map[string]interface{}{"id": "vpc-dev"}),
		newRes("aws_flow_log", "prod_flow", map[string]interface{}{"vpc_id": "vpc-prod"}),
	}
	findings := r.EvaluateAll(resources)
	assert.Len(t, findings, 1)
	assert.Contains(t, findings[0].Resource, "dev")
}
