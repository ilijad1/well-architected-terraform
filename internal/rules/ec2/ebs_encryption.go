package ec2

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&EBSEncryption{})
}

// EBSEncryption checks that EBS volumes have encryption enabled.
type EBSEncryption struct{}

func (r *EBSEncryption) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "EC2-002",
		Name:          "EBS Volume Encryption",
		Description:   "EBS volumes should have encryption enabled to protect data at rest.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_ebs_volume"},
		DocURL:        "https://docs.aws.amazon.com/ebs/latest/userguide/ebs-encryption.html",
	}
}

func (r *EBSEncryption) Evaluate(resource model.TerraformResource) []model.Finding {
	encrypted, ok := resource.GetBoolAttr("encrypted")
	if ok && encrypted {
		return nil
	}

	return []model.Finding{{
		RuleID:      "EC2-002",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityHigh,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "EBS volume does not have encryption enabled.",
		Remediation: "Set encrypted = true and optionally specify a kms_key_id.",
		DocURL:      r.Metadata().DocURL,
	}}
}
