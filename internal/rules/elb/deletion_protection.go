package elb

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&DeletionProtectionRule{})
}

type DeletionProtectionRule struct{}

func (r *DeletionProtectionRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "ELB-003",
		Name:          "Load Balancer Deletion Protection",
		Description:   "Load Balancers should have deletion protection enabled",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarReliability,
		ResourceTypes: []string{"aws_lb"},
		DocURL:        "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#deletion-protection",
	}
}

func (r *DeletionProtectionRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	deletionProtection, exists := resource.GetBoolAttr("enable_deletion_protection")
	if !exists || !deletionProtection {
		findings = append(findings, model.Finding{
			RuleID:      "ELB-003",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarReliability,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "Load balancer does not have deletion protection enabled",
			Remediation: "Set enable_deletion_protection to true to prevent accidental deletion",
		})
	}

	return findings
}
