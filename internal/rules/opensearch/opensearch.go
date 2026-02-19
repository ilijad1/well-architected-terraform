// Package opensearch contains Well-Architected rules for AWS OPENSEARCH resources.
package opensearch

import (
	"strings"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&EncryptAtRest{})
	engine.Register(&NodeToNode{})
	engine.Register(&EnforceHTTPS{})
	engine.Register(&VPCEndpoint{})
	engine.Register(&AuditLogs{})
	engine.Register(&AdvancedSecurity{})
	engine.Register(&TLSPolicy{})
}

type EncryptAtRest struct{}

func (r *EncryptAtRest) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID: "OS-001", Name: "OpenSearch Encrypt at Rest",
		Description: "OpenSearch domains should have encryption at rest enabled.",
		Severity:    model.SeverityHigh, Pillar: model.PillarSecurity,
		ResourceTypes: []string{"aws_opensearch_domain"},
	}
}

func (r *EncryptAtRest) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, b := range resource.GetBlocks("encrypt_at_rest") {
		if v, ok := b.GetBoolAttr("enabled"); ok && v {
			return nil
		}
	}
	return []model.Finding{{RuleID: "OS-001", RuleName: r.Metadata().Name, Severity: model.SeverityHigh, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "OpenSearch domain does not have encryption at rest enabled.", Remediation: "Add encrypt_at_rest block with enabled = true."}}
}

type NodeToNode struct{}

func (r *NodeToNode) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID: "OS-002", Name: "OpenSearch Node-to-Node Encryption",
		Description: "OpenSearch domains should have node-to-node encryption enabled.",
		Severity:    model.SeverityHigh, Pillar: model.PillarSecurity,
		ResourceTypes: []string{"aws_opensearch_domain"},
	}
}

func (r *NodeToNode) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, b := range resource.GetBlocks("node_to_node_encryption") {
		if v, ok := b.GetBoolAttr("enabled"); ok && v {
			return nil
		}
	}
	return []model.Finding{{RuleID: "OS-002", RuleName: r.Metadata().Name, Severity: model.SeverityHigh, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "OpenSearch domain does not have node-to-node encryption enabled.", Remediation: "Add node_to_node_encryption block with enabled = true."}}
}

type EnforceHTTPS struct{}

func (r *EnforceHTTPS) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID: "OS-003", Name: "OpenSearch Enforce HTTPS",
		Description: "OpenSearch domains should enforce HTTPS.",
		Severity:    model.SeverityHigh, Pillar: model.PillarSecurity,
		ResourceTypes: []string{"aws_opensearch_domain"},
	}
}

func (r *EnforceHTTPS) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, b := range resource.GetBlocks("domain_endpoint_options") {
		if v, ok := b.GetBoolAttr("enforce_https"); ok && v {
			return nil
		}
	}
	return []model.Finding{{RuleID: "OS-003", RuleName: r.Metadata().Name, Severity: model.SeverityHigh, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "OpenSearch domain does not enforce HTTPS.", Remediation: "Add domain_endpoint_options block with enforce_https = true."}}
}

type VPCEndpoint struct{}

func (r *VPCEndpoint) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID: "OS-004", Name: "OpenSearch VPC Endpoint",
		Description: "OpenSearch domains should be deployed within a VPC.",
		Severity:    model.SeverityHigh, Pillar: model.PillarSecurity,
		ResourceTypes: []string{"aws_opensearch_domain"},
	}
}

func (r *VPCEndpoint) Evaluate(resource model.TerraformResource) []model.Finding {
	if resource.HasBlock("vpc_options") {
		return nil
	}
	return []model.Finding{{RuleID: "OS-004", RuleName: r.Metadata().Name, Severity: model.SeverityHigh, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "OpenSearch domain is not deployed within a VPC.", Remediation: "Add vpc_options block with subnet_ids."}}
}

type AuditLogs struct{}

func (r *AuditLogs) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID: "OS-005", Name: "OpenSearch Audit Logs",
		Description: "OpenSearch domains should publish audit logs.",
		Severity:    model.SeverityMedium, Pillar: model.PillarSecurity,
		ResourceTypes: []string{"aws_opensearch_domain"},
	}
}

func (r *AuditLogs) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, b := range resource.GetBlocks("log_publishing_options") {
		if lt, ok := b.GetStringAttr("log_type"); ok && lt == "AUDIT_LOGS" {
			return nil
		}
	}
	return []model.Finding{{RuleID: "OS-005", RuleName: r.Metadata().Name, Severity: model.SeverityMedium, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "OpenSearch domain does not publish audit logs.", Remediation: "Add log_publishing_options block with log_type = \"AUDIT_LOGS\"."}}
}

type AdvancedSecurity struct{}

func (r *AdvancedSecurity) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID: "OS-006", Name: "OpenSearch Advanced Security",
		Description: "OpenSearch domains should have advanced security options enabled.",
		Severity:    model.SeverityHigh, Pillar: model.PillarSecurity,
		ResourceTypes: []string{"aws_opensearch_domain"},
	}
}

func (r *AdvancedSecurity) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, b := range resource.GetBlocks("advanced_security_options") {
		if v, ok := b.GetBoolAttr("enabled"); ok && v {
			return nil
		}
	}
	return []model.Finding{{RuleID: "OS-006", RuleName: r.Metadata().Name, Severity: model.SeverityHigh, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "OpenSearch domain does not have advanced security options enabled.", Remediation: "Add advanced_security_options block with enabled = true."}}
}

type TLSPolicy struct{}

func (r *TLSPolicy) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID: "OS-007", Name: "OpenSearch TLS 1.2 Policy",
		Description: "OpenSearch domains should use TLS 1.2 security policy.",
		Severity:    model.SeverityMedium, Pillar: model.PillarSecurity,
		ResourceTypes: []string{"aws_opensearch_domain"},
	}
}

func (r *TLSPolicy) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, b := range resource.GetBlocks("domain_endpoint_options") {
		if v, ok := b.GetStringAttr("tls_security_policy"); ok && strings.Contains(v, "TLS-1-2") {
			return nil
		}
	}
	return []model.Finding{{RuleID: "OS-007", RuleName: r.Metadata().Name, Severity: model.SeverityMedium, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "OpenSearch domain does not use TLS 1.2 security policy.", Remediation: "Set tls_security_policy to a policy containing TLS-1-2 in domain_endpoint_options."}}
}
