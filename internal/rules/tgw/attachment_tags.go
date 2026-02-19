package tgw

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// AttachmentTagsRule checks that TGW VPC attachments are tagged.
type AttachmentTagsRule struct{}

func init() {
	engine.Register(&AttachmentTagsRule{})
}

func (r *AttachmentTagsRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "TGW-005",
		Name:          "Transit Gateway VPC Attachment Missing Tags",
		Description:   "Transit Gateway VPC attachments should be tagged for cost allocation and identification.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarOperationalExcellence,
		ResourceTypes: []string{"aws_ec2_transit_gateway_vpc_attachment"},
	}
}

func (r *AttachmentTagsRule) Evaluate(resource model.TerraformResource) []model.Finding {
	tags, ok := resource.Attributes["tags"]
	if ok && tags != nil {
		if tagMap, ok := tags.(map[string]interface{}); ok && len(tagMap) > 0 {
			return nil
		}
	}

	return []model.Finding{{
		RuleID:      "TGW-005",
		RuleName:    "Transit Gateway VPC Attachment Missing Tags",
		Severity:    model.SeverityLow,
		Pillar:      model.PillarOperationalExcellence,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "This Transit Gateway VPC attachment has no tags. Tags are essential for cost allocation and identifying which account/VPC the attachment belongs to.",
		Remediation: "Add tags including at minimum Name, Environment, and Owner.",
	}}
}
