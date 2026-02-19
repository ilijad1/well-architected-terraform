package vpc

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&DefaultSG{})
}

type DefaultSG struct{}

func (r *DefaultSG) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "VPC-003",
		Name:          "Default Security Group Restricts All Traffic",
		Description:   "The default security group should restrict all inbound and outbound traffic.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_default_security_group"},
	}
}

func (r *DefaultSG) Evaluate(resource model.TerraformResource) []model.Finding {
	hasIngress := resource.HasBlock("ingress")
	hasEgress := resource.HasBlock("egress")

	if !hasIngress && !hasEgress {
		return nil
	}

	return []model.Finding{{
		RuleID:      "VPC-003",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityHigh,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "Default security group has ingress or egress rules defined. It should restrict all traffic.",
		Remediation: "Remove all ingress and egress blocks from the default security group to restrict all traffic.",
	}}
}
