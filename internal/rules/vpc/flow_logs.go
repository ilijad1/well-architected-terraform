package vpc

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&FlowLogs{})
}

// FlowLogs checks that VPCs have flow logs enabled.
// Note: This is a presence check — it verifies that aws_flow_log resources exist
// and have required attributes. Cross-resource validation (ensuring every VPC has
// a flow log) requires Phase 2 cross-resource rules.
type FlowLogs struct{}

func (r *FlowLogs) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "VPC-002",
		Name:          "VPC Flow Logs",
		Description:   "VPCs should have flow logs enabled for network monitoring and security analysis.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarOperationalExcellence,
		ResourceTypes: []string{"aws_flow_log"},
	}
}

func (r *FlowLogs) Evaluate(resource model.TerraformResource) []model.Finding {
	// If the resource exists, flow logs are being configured.
	// Check that traffic_type is set (preferably to "ALL").
	trafficType, ok := resource.GetStringAttr("traffic_type")
	if ok && trafficType == "ALL" {
		return nil
	}

	if !ok {
		return []model.Finding{{
			RuleID:      "VPC-002",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarOperationalExcellence,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "VPC flow log does not specify traffic_type.",
			Remediation: "Set traffic_type = \"ALL\" to capture both accepted and rejected traffic.",
		}}
	}

	return nil
}
