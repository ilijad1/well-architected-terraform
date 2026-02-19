package tgw

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// AutoAcceptRule checks that Transit Gateways do not auto-accept shared attachments.
type AutoAcceptRule struct{}

func init() {
	engine.Register(&AutoAcceptRule{})
}

func (r *AutoAcceptRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "TGW-001",
		Name:          "Transit Gateway Auto-Accept Shared Attachments",
		Description:   "Transit Gateways should not automatically accept shared attachments to maintain network segmentation control.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_ec2_transit_gateway"},
	}
}

func (r *AutoAcceptRule) Evaluate(resource model.TerraformResource) []model.Finding {
	val, ok := resource.GetStringAttr("auto_accept_shared_attachments")
	if ok && val == "enable" {
		return []model.Finding{{
			RuleID:      "TGW-001",
			RuleName:    "Transit Gateway Auto-Accept Shared Attachments",
			Severity:    model.SeverityHigh,
			Pillar:      model.PillarSecurity,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "This Transit Gateway auto-accepts shared attachments. Any account with RAM sharing access can attach without approval.",
			Remediation: "Set auto_accept_shared_attachments = \"disable\" and manually approve VPC attachments.",
		}}
	}
	return nil
}
