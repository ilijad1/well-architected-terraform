package dax

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&EncryptionAtRest{})
	engine.Register(&EndpointEncryption{})
}

type EncryptionAtRest struct{}

func (r *EncryptionAtRest) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "DAX-001", Name: "DAX Cluster Encryption at Rest", Description: "DAX clusters should have server-side encryption enabled.", Severity: model.SeverityHigh, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_dax_cluster"}}
}

func (r *EncryptionAtRest) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, b := range resource.GetBlocks("server_side_encryption") {
		if v, ok := b.GetBoolAttr("enabled"); ok && v {
			return nil
		}
	}
	return []model.Finding{{RuleID: "DAX-001", RuleName: r.Metadata().Name, Severity: model.SeverityHigh, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "DAX cluster does not have server-side encryption enabled.", Remediation: "Add server_side_encryption block with enabled = true."}}
}

type EndpointEncryption struct{}

func (r *EndpointEncryption) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "DAX-002", Name: "DAX Cluster Endpoint Encryption", Description: "DAX clusters should use TLS for endpoint encryption.", Severity: model.SeverityHigh, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_dax_cluster"}}
}

func (r *EndpointEncryption) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetStringAttr("cluster_endpoint_encryption_type"); ok && v == "TLS" {
		return nil
	}
	return []model.Finding{{RuleID: "DAX-002", RuleName: r.Metadata().Name, Severity: model.SeverityHigh, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "DAX cluster does not use TLS for endpoint encryption.", Remediation: "Set cluster_endpoint_encryption_type = \"TLS\"."}}
}
