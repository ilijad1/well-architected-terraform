// Package workspaces contains Well-Architected rules for AWS WORKSPACES resources.
package workspaces

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&VolumeEncryption{})
	engine.Register(&CMKEncryption{})
}

type VolumeEncryption struct{}

func (r *VolumeEncryption) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "WS-001",
		Name:          "WorkSpaces Volume Encryption",
		Description:   "WorkSpaces should have root and user volume encryption enabled.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_workspaces_workspace"},
	}
}

func (r *VolumeEncryption) Evaluate(resource model.TerraformResource) []model.Finding {
	rootEnc, rootOk := resource.GetBoolAttr("root_volume_encryption_enabled")
	userEnc, userOk := resource.GetBoolAttr("user_volume_encryption_enabled")
	if rootOk && rootEnc && userOk && userEnc {
		return nil
	}
	return []model.Finding{{
		RuleID:      "WS-001",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityHigh,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "WorkSpaces does not have both root and user volume encryption enabled.",
		Remediation: "Set root_volume_encryption_enabled = true and user_volume_encryption_enabled = true.",
	}}
}

type CMKEncryption struct{}

func (r *CMKEncryption) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "WS-002",
		Name:          "WorkSpaces CMK Encryption",
		Description:   "WorkSpaces should use a customer-managed KMS key for volume encryption.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_workspaces_workspace"},
	}
}

func (r *CMKEncryption) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetStringAttr("volume_encryption_key"); ok && v != "" {
		return nil
	}
	return []model.Finding{{
		RuleID:      "WS-002",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "WorkSpaces does not use a customer-managed KMS key.",
		Remediation: "Set volume_encryption_key to a KMS key ARN.",
	}}
}
