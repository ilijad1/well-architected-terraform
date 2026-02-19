package vpc

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&SubnetPublicIP{})
}

// SubnetPublicIP checks that subnets do not auto-assign public IP addresses.
type SubnetPublicIP struct{}

func (r *SubnetPublicIP) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "VPC-005",
		Name:          "Subnet Auto-Assign Public IP Disabled",
		Description:   "Subnets should not automatically assign public IP addresses to instances launched within them.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_subnet"},
		DocURL:        "https://docs.aws.amazon.com/vpc/latest/userguide/configure-subnets.html",
	}
}

func (r *SubnetPublicIP) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetBoolAttr("map_public_ip_on_launch"); ok && v {
		return []model.Finding{{
			RuleID:      "VPC-005",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityHigh,
			Pillar:      model.PillarSecurity,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "Subnet has map_public_ip_on_launch = true, which automatically assigns public IPs to instances.",
			Remediation: "Set map_public_ip_on_launch = false. Use Elastic IPs or load balancers for controlled public access.",
			DocURL:      r.Metadata().DocURL,
		}}
	}
	return nil
}
