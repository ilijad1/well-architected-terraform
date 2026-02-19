package tgw

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// DefaultRouteTableAssociationRule checks that TGW default route table association is disabled.
type DefaultRouteTableAssociationRule struct{}

func init() {
	engine.Register(&DefaultRouteTableAssociationRule{})
}

func (r *DefaultRouteTableAssociationRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "TGW-002",
		Name:          "Transit Gateway Default Route Table Association Enabled",
		Description:   "Transit Gateways should not use default route table association; use explicit route tables for network segmentation.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_ec2_transit_gateway"},
	}
}

func (r *DefaultRouteTableAssociationRule) Evaluate(resource model.TerraformResource) []model.Finding {
	val, ok := resource.GetStringAttr("default_route_table_association")
	// Default is "enable" if not set
	if !ok || val == "enable" {
		return []model.Finding{{
			RuleID:      "TGW-002",
			RuleName:    "Transit Gateway Default Route Table Association Enabled",
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarSecurity,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "This Transit Gateway uses the default route table for all attachments, breaking network segmentation. All VPCs can route to each other by default.",
			Remediation: "Set default_route_table_association = \"disable\" and create explicit route table associations per attachment for proper segmentation.",
		}}
	}
	return nil
}

// DefaultRouteTablePropagationRule checks that TGW default route table propagation is disabled.
type DefaultRouteTablePropagationRule struct{}

func init() {
	engine.Register(&DefaultRouteTablePropagationRule{})
}

func (r *DefaultRouteTablePropagationRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "TGW-003",
		Name:          "Transit Gateway Default Route Table Propagation Enabled",
		Description:   "Transit Gateways should not use default route table propagation; use explicit propagation for network segmentation.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_ec2_transit_gateway"},
	}
}

func (r *DefaultRouteTablePropagationRule) Evaluate(resource model.TerraformResource) []model.Finding {
	val, ok := resource.GetStringAttr("default_route_table_propagation")
	if !ok || val == "enable" {
		return []model.Finding{{
			RuleID:      "TGW-003",
			RuleName:    "Transit Gateway Default Route Table Propagation Enabled",
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarSecurity,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "This Transit Gateway propagates all attachment routes to the default route table, breaking network segmentation.",
			Remediation: "Set default_route_table_propagation = \"disable\" and configure explicit route propagation per route table.",
		}}
	}
	return nil
}

// DNSSupportRule checks that DNS support is enabled on the Transit Gateway.
type DNSSupportRule struct{}

func init() {
	engine.Register(&DNSSupportRule{})
}

func (r *DNSSupportRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "TGW-004",
		Name:          "Transit Gateway DNS Support Disabled",
		Description:   "Transit Gateways should have DNS support enabled for proper cross-VPC DNS resolution.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarReliability,
		ResourceTypes: []string{"aws_ec2_transit_gateway"},
	}
}

func (r *DNSSupportRule) Evaluate(resource model.TerraformResource) []model.Finding {
	val, ok := resource.GetStringAttr("dns_support")
	if ok && val == "disable" {
		return []model.Finding{{
			RuleID:      "TGW-004",
			RuleName:    "Transit Gateway DNS Support Disabled",
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarReliability,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "DNS support is disabled on this Transit Gateway. Cross-VPC DNS resolution will not work through the TGW.",
			Remediation: "Set dns_support = \"enable\" to allow DNS resolution across VPC attachments.",
		}}
	}
	return nil
}
