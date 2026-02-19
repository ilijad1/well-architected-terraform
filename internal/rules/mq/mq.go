// Package mq contains Well-Architected rules for AWS MQ resources.
package mq

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&Logging{})
	engine.Register(&NotPublic{})
	engine.Register(&AutoMinorVersion{})
	engine.Register(&CMKEncryption{})
}

type Logging struct{}

func (r *Logging) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "MQ-001", Name: "MQ Broker Logging", Description: "MQ brokers should have logging enabled.", Severity: model.SeverityMedium, Pillar: model.PillarOperationalExcellence, ResourceTypes: []string{"aws_mq_broker"}}
}

func (r *Logging) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, b := range resource.GetBlocks("logs") {
		if v, ok := b.GetBoolAttr("general"); ok && v {
			return nil
		}
		if v, ok := b.GetBoolAttr("audit"); ok && v {
			return nil
		}
	}
	return []model.Finding{{RuleID: "MQ-001", RuleName: r.Metadata().Name, Severity: model.SeverityMedium, Pillar: model.PillarOperationalExcellence, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "MQ broker does not have logging enabled.", Remediation: "Add logs block with general = true or audit = true."}}
}

type NotPublic struct{}

func (r *NotPublic) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "MQ-002", Name: "MQ Broker Not Publicly Accessible", Description: "MQ brokers should not be publicly accessible.", Severity: model.SeverityCritical, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_mq_broker"}}
}

func (r *NotPublic) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetBoolAttr("publicly_accessible"); ok && v {
		return []model.Finding{{RuleID: "MQ-002", RuleName: r.Metadata().Name, Severity: model.SeverityCritical, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "MQ broker is publicly accessible.", Remediation: "Set publicly_accessible = false."}}
	}
	return nil
}

type AutoMinorVersion struct{}

func (r *AutoMinorVersion) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "MQ-003", Name: "MQ Auto Minor Version Upgrade", Description: "MQ brokers should have auto minor version upgrade enabled.", Severity: model.SeverityMedium, Pillar: model.PillarOperationalExcellence, ResourceTypes: []string{"aws_mq_broker"}}
}

func (r *AutoMinorVersion) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetBoolAttr("auto_minor_version_upgrade"); ok && v {
		return nil
	}
	return []model.Finding{{RuleID: "MQ-003", RuleName: r.Metadata().Name, Severity: model.SeverityMedium, Pillar: model.PillarOperationalExcellence, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "MQ broker does not have auto minor version upgrade enabled.", Remediation: "Set auto_minor_version_upgrade = true."}}
}

type CMKEncryption struct{}

func (r *CMKEncryption) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "MQ-004", Name: "MQ Broker CMK Encryption", Description: "MQ brokers should use a customer-managed KMS key.", Severity: model.SeverityMedium, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_mq_broker"}}
}

func (r *CMKEncryption) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, b := range resource.GetBlocks("encryption_options") {
		useOwned, _ := b.GetBoolAttr("use_aws_owned_key")
		kmsKey, hasKey := b.GetStringAttr("kms_key_id")
		if !useOwned && hasKey && kmsKey != "" {
			return nil
		}
	}
	return []model.Finding{{RuleID: "MQ-004", RuleName: r.Metadata().Name, Severity: model.SeverityMedium, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "MQ broker does not use a customer-managed KMS key.", Remediation: "Add encryption_options with use_aws_owned_key = false and kms_key_id set."}}
}
