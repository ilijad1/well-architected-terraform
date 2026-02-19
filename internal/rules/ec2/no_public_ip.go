package ec2

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&NoPublicIP{})
}

// NoPublicIP checks that EC2 instances do not have public IP addresses auto-assigned.
type NoPublicIP struct{}

func (r *NoPublicIP) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "EC2-008",
		Name:          "EC2 Instance No Public IP",
		Description:   "EC2 instances should not be launched with a public IP address unless explicitly required.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_instance"},
		DocURL:        "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html",
	}
}

func (r *NoPublicIP) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetBoolAttr("associate_public_ip_address"); ok && v {
		return []model.Finding{{
			RuleID:      "EC2-008",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityHigh,
			Pillar:      model.PillarSecurity,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "EC2 instance has associate_public_ip_address = true, exposing it to the internet.",
			Remediation: "Set associate_public_ip_address = false and use a NAT gateway or VPN for outbound access.",
			DocURL:      r.Metadata().DocURL,
		}}
	}
	return nil
}
