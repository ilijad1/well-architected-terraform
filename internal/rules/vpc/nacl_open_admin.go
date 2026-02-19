package vpc

import (
	"fmt"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&NACLOpenAdmin{})
}

type NACLOpenAdmin struct{}

func (r *NACLOpenAdmin) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "VPC-004",
		Name:          "NACL No Open Admin Ports",
		Description:   "Network ACL rules should not allow unrestricted access to admin ports (22, 3389).",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_network_acl_rule"},
	}
}

func (r *NACLOpenAdmin) Evaluate(resource model.TerraformResource) []model.Finding {
	ruleAction, _ := resource.GetStringAttr("rule_action")
	if ruleAction != "allow" {
		return nil
	}

	egress, _ := resource.GetBoolAttr("egress")
	if egress {
		return nil
	}

	cidr, _ := resource.GetStringAttr("cidr_block")
	ipv6Cidr, _ := resource.GetStringAttr("ipv6_cidr_block")
	if cidr != "0.0.0.0/0" && ipv6Cidr != "::/0" {
		return nil
	}

	fromPort, hasFrom := resource.GetNumberAttr("from_port")
	toPort, hasTo := resource.GetNumberAttr("to_port")
	if !hasFrom || !hasTo {
		return nil
	}

	adminPorts := map[int]string{22: "SSH", 3389: "RDP"}
	for port, service := range adminPorts {
		if int(fromPort) <= port && int(toPort) >= port {
			return []model.Finding{{
				RuleID:      "VPC-004",
				RuleName:    r.Metadata().Name,
				Severity:    model.SeverityHigh,
				Pillar:      model.PillarSecurity,
				Resource:    resource.Address(),
				File:        resource.File,
				Line:        resource.Line,
				Description: fmt.Sprintf("Network ACL rule allows unrestricted access (0.0.0.0/0) to port %d (%s).", port, service),
				Remediation: fmt.Sprintf("Restrict the NACL rule to specific CIDR blocks instead of 0.0.0.0/0 for port %d.", port),
			}}
		}
	}

	return nil
}
