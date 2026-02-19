package vpc

import (
	"strings"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&RouteToIGW{})
}

// RouteToIGW checks that route table entries don't have unrestricted routes to an internet gateway.
type RouteToIGW struct{}

func (r *RouteToIGW) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "VPC-006",
		Name:          "No Unrestricted Route to Internet Gateway",
		Description:   "Route tables should not have a default route (0.0.0.0/0 or ::/0) pointing directly to an internet gateway without additional controls.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_route"},
		DocURL:        "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Route_Tables.html",
	}
}

func (r *RouteToIGW) Evaluate(resource model.TerraformResource) []model.Finding {
	cidr, hasCIDR := resource.GetStringAttr("destination_cidr_block")
	cidrv6, hasCIDRv6 := resource.GetStringAttr("destination_ipv6_cidr_block")

	isDefaultRoute := (hasCIDR && cidr == "0.0.0.0/0") || (hasCIDRv6 && cidrv6 == "::/0")
	if !isDefaultRoute {
		return nil
	}

	gwID, ok := resource.GetStringAttr("gateway_id")
	if ok && strings.HasPrefix(gwID, "igw-") {
		return []model.Finding{{
			RuleID:      "VPC-006",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityHigh,
			Pillar:      model.PillarSecurity,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "Route table has an unrestricted default route (0.0.0.0/0 or ::/0) pointing to an internet gateway.",
			Remediation: "Ensure this route is intentional for public subnets only. Use security groups and NACLs to restrict inbound access.",
			DocURL:      r.Metadata().DocURL,
		}}
	}
	return nil
}
