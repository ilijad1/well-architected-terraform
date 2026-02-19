package ec2

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&EBSDefaultEncryption{})
}

type EBSDefaultEncryption struct{}

func (r *EBSDefaultEncryption) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "EC2-007",
		Name:          "EBS Encryption By Default",
		Description:   "EBS encryption by default should be enabled to ensure all new volumes are encrypted.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_ebs_encryption_by_default"},
	}
}

func (r *EBSDefaultEncryption) Evaluate(resource model.TerraformResource) []model.Finding {
	enabled, ok := resource.GetBoolAttr("enabled")
	if ok && enabled {
		return nil
	}

	return []model.Finding{{
		RuleID:      "EC2-007",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityHigh,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "EBS encryption by default is not enabled.",
		Remediation: "Set enabled = true on the aws_ebs_encryption_by_default resource.",
	}}
}
