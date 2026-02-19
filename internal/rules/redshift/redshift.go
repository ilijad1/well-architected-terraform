// Package redshift contains Well-Architected rules for AWS REDSHIFT resources.
package redshift

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&Encryption{})
	engine.Register(&PublicAccess{})
	engine.Register(&Logging{})
	engine.Register(&RequireSSL{})
	engine.Register(&EnhancedVPCRouting{})
	engine.Register(&MultiNode{})
}

type Encryption struct{}

func (r *Encryption) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "RS-001", Name: "Redshift Cluster Encryption", Description: "Redshift clusters should have encryption enabled.", Severity: model.SeverityHigh, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_redshift_cluster"}}
}

func (r *Encryption) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetBoolAttr("encrypted"); ok && v {
		return nil
	}
	return []model.Finding{{RuleID: "RS-001", RuleName: r.Metadata().Name, Severity: model.SeverityHigh, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "Redshift cluster does not have encryption enabled.", Remediation: "Set encrypted = true."}}
}

type PublicAccess struct{}

func (r *PublicAccess) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "RS-002", Name: "Redshift Not Publicly Accessible", Description: "Redshift clusters should not be publicly accessible.", Severity: model.SeverityCritical, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_redshift_cluster"}}
}

func (r *PublicAccess) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetBoolAttr("publicly_accessible"); ok && v {
		return []model.Finding{{RuleID: "RS-002", RuleName: r.Metadata().Name, Severity: model.SeverityCritical, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "Redshift cluster is publicly accessible.", Remediation: "Set publicly_accessible = false."}}
	}
	return nil
}

type Logging struct{}

func (r *Logging) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "RS-003", Name: "Redshift Audit Logging", Description: "Redshift clusters should have audit logging enabled.", Severity: model.SeverityMedium, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_redshift_cluster"}}
}

func (r *Logging) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, b := range resource.GetBlocks("logging") {
		if v, ok := b.GetBoolAttr("enable"); ok && v {
			return nil
		}
	}
	return []model.Finding{{RuleID: "RS-003", RuleName: r.Metadata().Name, Severity: model.SeverityMedium, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "Redshift cluster does not have audit logging enabled.", Remediation: "Add logging block with enable = true."}}
}

type RequireSSL struct{}

func (r *RequireSSL) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "RS-004", Name: "Redshift Require SSL", Description: "Redshift parameter groups should require SSL connections.", Severity: model.SeverityHigh, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_redshift_parameter_group"}}
}

func (r *RequireSSL) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, p := range resource.GetBlocks("parameter") {
		name, _ := p.GetStringAttr("name")
		value, _ := p.GetStringAttr("value")
		if name == "require_ssl" && value == "true" {
			return nil
		}
	}
	return []model.Finding{{RuleID: "RS-004", RuleName: r.Metadata().Name, Severity: model.SeverityHigh, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "Redshift parameter group does not require SSL.", Remediation: "Add parameter with name = \"require_ssl\" and value = \"true\"."}}
}

type EnhancedVPCRouting struct{}

func (r *EnhancedVPCRouting) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "RS-005", Name: "Redshift Enhanced VPC Routing", Description: "Redshift clusters should have enhanced VPC routing enabled.", Severity: model.SeverityMedium, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_redshift_cluster"}}
}

func (r *EnhancedVPCRouting) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetBoolAttr("enhanced_vpc_routing"); ok && v {
		return nil
	}
	return []model.Finding{{RuleID: "RS-005", RuleName: r.Metadata().Name, Severity: model.SeverityMedium, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "Redshift cluster does not have enhanced VPC routing enabled.", Remediation: "Set enhanced_vpc_routing = true."}}
}

type MultiNode struct{}

func (r *MultiNode) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "RS-006", Name: "Redshift Multi-Node", Description: "Redshift clusters should use multi-node configuration for reliability.", Severity: model.SeverityMedium, Pillar: model.PillarReliability, ResourceTypes: []string{"aws_redshift_cluster"}}
}

func (r *MultiNode) Evaluate(resource model.TerraformResource) []model.Finding {
	if ct, ok := resource.GetStringAttr("cluster_type"); ok && ct == "multi-node" {
		return nil
	}
	if n, ok := resource.GetNumberAttr("number_of_nodes"); ok && n > 1 {
		return nil
	}
	return []model.Finding{{RuleID: "RS-006", RuleName: r.Metadata().Name, Severity: model.SeverityMedium, Pillar: model.PillarReliability, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "Redshift cluster is not using multi-node configuration.", Remediation: "Set cluster_type = \"multi-node\" and number_of_nodes > 1."}}
}
