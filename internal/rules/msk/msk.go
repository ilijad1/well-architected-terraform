package msk

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&EncryptionInTransit{})
	engine.Register(&NoPublicAccess{})
	engine.Register(&LoggingInfo{})
	engine.Register(&EnhancedMonitoring{})
}

type EncryptionInTransit struct{}

func (r *EncryptionInTransit) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "MSK-001", Name: "MSK Encryption in Transit", Description: "MSK clusters should have encryption in transit configured with TLS.", Severity: model.SeverityHigh, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_msk_cluster"}}
}

func (r *EncryptionInTransit) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, ei := range resource.GetBlocks("encryption_info") {
		for _, eit := range ei.Blocks["encryption_in_transit"] {
			cb, _ := eit.GetStringAttr("client_broker")
			ic, icOk := eit.GetBoolAttr("in_cluster")
			if cb == "TLS" && (!icOk || ic) {
				return nil
			}
		}
	}
	return []model.Finding{{RuleID: "MSK-001", RuleName: r.Metadata().Name, Severity: model.SeverityHigh, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "MSK cluster does not have proper encryption in transit.", Remediation: "Add encryption_info block with encryption_in_transit: client_broker = \"TLS\" and in_cluster = true."}}
}

type NoPublicAccess struct{}

func (r *NoPublicAccess) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "MSK-002", Name: "MSK No Public Access", Description: "MSK clusters should not have public access enabled.", Severity: model.SeverityCritical, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_msk_cluster"}}
}

func (r *NoPublicAccess) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, bng := range resource.GetBlocks("broker_node_group_info") {
		for _, ci := range bng.Blocks["connectivity_info"] {
			for _, pa := range ci.Blocks["public_access"] {
				if v, ok := pa.GetStringAttr("type"); ok && v != "DISABLED" {
					return []model.Finding{{RuleID: "MSK-002", RuleName: r.Metadata().Name, Severity: model.SeverityCritical, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "MSK cluster has public access enabled.", Remediation: "Set public_access type to \"DISABLED\" or remove the block."}}
				}
			}
		}
	}
	return nil
}

type LoggingInfo struct{}

func (r *LoggingInfo) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "MSK-003", Name: "MSK Logging Configuration", Description: "MSK clusters should have logging configured.", Severity: model.SeverityMedium, Pillar: model.PillarOperationalExcellence, ResourceTypes: []string{"aws_msk_cluster"}}
}

func (r *LoggingInfo) Evaluate(resource model.TerraformResource) []model.Finding {
	if resource.HasBlock("logging_info") {
		return nil
	}
	return []model.Finding{{RuleID: "MSK-003", RuleName: r.Metadata().Name, Severity: model.SeverityMedium, Pillar: model.PillarOperationalExcellence, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "MSK cluster does not have logging configured.", Remediation: "Add logging_info block with broker_logs configuration."}}
}

type EnhancedMonitoring struct{}

func (r *EnhancedMonitoring) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "MSK-004", Name: "MSK Enhanced Monitoring", Description: "MSK clusters should have enhanced monitoring enabled.", Severity: model.SeverityLow, Pillar: model.PillarOperationalExcellence, ResourceTypes: []string{"aws_msk_cluster"}}
}

func (r *EnhancedMonitoring) Evaluate(resource model.TerraformResource) []model.Finding {
	em, ok := resource.GetStringAttr("enhanced_monitoring")
	if ok && em != "DEFAULT" {
		return nil
	}
	return []model.Finding{{RuleID: "MSK-004", RuleName: r.Metadata().Name, Severity: model.SeverityLow, Pillar: model.PillarOperationalExcellence, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "MSK cluster does not have enhanced monitoring enabled.", Remediation: "Set enhanced_monitoring to \"PER_BROKER\" or \"PER_TOPIC_PER_BROKER\"."}}
}
