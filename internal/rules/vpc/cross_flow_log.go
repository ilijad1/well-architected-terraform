// Package vpc contains Well-Architected rules for AWS VPC resources.
package vpc

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// CrossFlowLogRule checks that every VPC has a corresponding aws_flow_log resource.
type CrossFlowLogRule struct{}

func init() {
	engine.RegisterCross(&CrossFlowLogRule{})
}

func (r *CrossFlowLogRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "VPC-007",
		Name:          "VPC Missing Flow Logs",
		Description:   "Every VPC should have flow logs enabled for network traffic monitoring and security analysis.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_vpc", "aws_flow_log"},
		ComplianceFrameworks: map[string][]string{
			"CIS": {"3.9"},
		},
	}
}

func (r *CrossFlowLogRule) EvaluateAll(resources []model.TerraformResource) []model.Finding {
	// Collect VPC IDs/addresses that have flow logs
	vpcsWithFlowLogs := make(map[string]bool)
	for _, res := range resources {
		if res.Type == "aws_flow_log" {
			vpcID, ok := res.GetStringAttr("vpc_id")
			if ok {
				vpcsWithFlowLogs[vpcID] = true
			}
		}
	}

	var findings []model.Finding
	for _, res := range resources {
		if res.Type != "aws_vpc" {
			continue
		}

		vpcID, _ := res.GetStringAttr("id")

		if !vpcsWithFlowLogs[vpcID] && !vpcsWithFlowLogs[res.Address()] {
			findings = append(findings, model.Finding{
				RuleID:      "VPC-007",
				RuleName:    "VPC Missing Flow Logs",
				Severity:    model.SeverityMedium,
				Pillar:      model.PillarSecurity,
				Resource:    res.Address(),
				File:        res.File,
				Line:        res.Line,
				Description: "This VPC has no aws_flow_log resource associated with it. VPC flow logs are essential for network traffic analysis, security monitoring, and incident investigation.",
				Remediation: "Add an aws_flow_log resource with vpc_id pointing to this VPC, traffic_type set to ALL, and a log destination (CloudWatch Logs or S3).",
			})
		}
	}

	return findings
}
