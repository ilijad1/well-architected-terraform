// Package eks contains Well-Architected rules for AWS EKS resources.
package eks

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&ClusterLogging{})
}

type ClusterLogging struct{}

func (r *ClusterLogging) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "EKS-002",
		Name:          "EKS Cluster Audit Logging",
		Description:   "Ensures EKS clusters have audit logging enabled",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarOperationalExcellence,
		ResourceTypes: []string{"aws_eks_cluster"},
		DocURL:        "https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html",
	}
}

func (r *ClusterLogging) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	logTypes, ok := resource.Attributes["enabled_cluster_log_types"].([]interface{})
	if !ok || len(logTypes) == 0 {
		findings = append(findings, model.Finding{
			RuleID:      "EKS-002",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarOperationalExcellence,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "EKS cluster does not have cluster logging enabled",
			Remediation: "Enable cluster logging by setting enabled_cluster_log_types to include 'audit' and other log types (api, authenticator, controllerManager, scheduler)",
			DocURL:      r.Metadata().DocURL,
		})
		return findings
	}

	hasAuditLog := false
	for _, logType := range logTypes {
		if logTypeStr, ok := logType.(string); ok && logTypeStr == "audit" {
			hasAuditLog = true
			break
		}
	}

	if !hasAuditLog {
		findings = append(findings, model.Finding{
			RuleID:      "EKS-002",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarOperationalExcellence,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "EKS cluster does not have audit logging enabled",
			Remediation: "Add 'audit' to the enabled_cluster_log_types list to enable audit logging for security and compliance monitoring",
			DocURL:      r.Metadata().DocURL,
		})
	}

	return findings
}
