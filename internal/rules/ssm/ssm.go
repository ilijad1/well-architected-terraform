package ssm

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&DocumentPublicAccess{})
}

type DocumentPublicAccess struct{}

func (r *DocumentPublicAccess) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "SSM-001", Name: "SSM Document Public Access", Description: "SSM documents should not be shared publicly.", Severity: model.SeverityHigh, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_ssm_document"}}
}

func (r *DocumentPublicAccess) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, p := range resource.GetBlocks("permissions") {
		if v, ok := p.GetStringAttr("account_ids"); ok && v == "all" {
			return []model.Finding{{RuleID: "SSM-001", RuleName: r.Metadata().Name, Severity: model.SeverityHigh, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "SSM document is shared publicly.", Remediation: "Remove permissions block or restrict account_ids to specific accounts."}}
		}
	}
	return nil
}
