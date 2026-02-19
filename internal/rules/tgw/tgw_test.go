package tgw

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

// --- TGW-001: Auto Accept ---

func TestAutoAccept_Enabled(t *testing.T) {
	r := &AutoAcceptRule{}
	findings := r.Evaluate(res("aws_ec2_transit_gateway", "tgw", map[string]interface{}{
		"auto_accept_shared_attachments": "enable",
	}))
	assert.Len(t, findings, 1)
	assert.Equal(t, "TGW-001", findings[0].RuleID)
}

func TestAutoAccept_Disabled(t *testing.T) {
	r := &AutoAcceptRule{}
	findings := r.Evaluate(res("aws_ec2_transit_gateway", "tgw", map[string]interface{}{
		"auto_accept_shared_attachments": "disable",
	}))
	assert.Empty(t, findings)
}

func TestAutoAccept_NotSet(t *testing.T) {
	r := &AutoAcceptRule{}
	findings := r.Evaluate(res("aws_ec2_transit_gateway", "tgw", map[string]interface{}{}))
	assert.Empty(t, findings) // default is disable
}

// --- TGW-002: Default Route Table Association ---

func TestDefaultRouteTableAssociation_Enabled(t *testing.T) {
	r := &DefaultRouteTableAssociationRule{}
	findings := r.Evaluate(res("aws_ec2_transit_gateway", "tgw", map[string]interface{}{
		"default_route_table_association": "enable",
	}))
	assert.Len(t, findings, 1)
	assert.Equal(t, "TGW-002", findings[0].RuleID)
}

func TestDefaultRouteTableAssociation_Disabled(t *testing.T) {
	r := &DefaultRouteTableAssociationRule{}
	findings := r.Evaluate(res("aws_ec2_transit_gateway", "tgw", map[string]interface{}{
		"default_route_table_association": "disable",
	}))
	assert.Empty(t, findings)
}

// --- TGW-003: Default Route Table Propagation ---

func TestDefaultRouteTablePropagation_Enabled(t *testing.T) {
	r := &DefaultRouteTablePropagationRule{}
	findings := r.Evaluate(res("aws_ec2_transit_gateway", "tgw", map[string]interface{}{
		"default_route_table_propagation": "enable",
	}))
	assert.Len(t, findings, 1)
	assert.Equal(t, "TGW-003", findings[0].RuleID)
}

func TestDefaultRouteTablePropagation_Disabled(t *testing.T) {
	r := &DefaultRouteTablePropagationRule{}
	findings := r.Evaluate(res("aws_ec2_transit_gateway", "tgw", map[string]interface{}{
		"default_route_table_propagation": "disable",
	}))
	assert.Empty(t, findings)
}

// --- TGW-004: DNS Support ---

func TestDNSSupport_Disabled(t *testing.T) {
	r := &DNSSupportRule{}
	findings := r.Evaluate(res("aws_ec2_transit_gateway", "tgw", map[string]interface{}{
		"dns_support": "disable",
	}))
	assert.Len(t, findings, 1)
	assert.Equal(t, "TGW-004", findings[0].RuleID)
}

func TestDNSSupport_Enabled(t *testing.T) {
	r := &DNSSupportRule{}
	findings := r.Evaluate(res("aws_ec2_transit_gateway", "tgw", map[string]interface{}{
		"dns_support": "enable",
	}))
	assert.Empty(t, findings)
}

// --- TGW-005: Attachment Tags ---

func TestAttachmentTags_Missing(t *testing.T) {
	r := &AttachmentTagsRule{}
	findings := r.Evaluate(res("aws_ec2_transit_gateway_vpc_attachment", "att", map[string]interface{}{}))
	assert.Len(t, findings, 1)
	assert.Equal(t, "TGW-005", findings[0].RuleID)
}

func TestAttachmentTags_Present(t *testing.T) {
	r := &AttachmentTagsRule{}
	findings := r.Evaluate(res("aws_ec2_transit_gateway_vpc_attachment", "att", map[string]interface{}{
		"tags": map[string]interface{}{"Name": "prod-vpc"},
	}))
	assert.Empty(t, findings)
}
