// Package inspector contains Well-Architected rules for AWS INSPECTOR resources.
package inspector

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&InspectorEnabled{})
}

// InspectorEnabled checks that AWS Inspector v2 is enabled for vulnerability management.
type InspectorEnabled struct{}

func (r *InspectorEnabled) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "INS-001",
		Name:          "AWS Inspector Enabled",
		Description:   "AWS Inspector v2 should be enabled to continuously scan for software vulnerabilities and network exposures.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_inspector2_enabler"},
		DocURL:        "https://docs.aws.amazon.com/inspector/latest/user/getting_started_tutorial.html",
	}
}

func (r *InspectorEnabled) Evaluate(resource model.TerraformResource) []model.Finding {
	// Check that at least one resource type is being scanned
	resourceTypes, ok := resource.Attributes["resource_types"]
	if !ok {
		return []model.Finding{{
			RuleID:      "INS-001",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarSecurity,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "AWS Inspector v2 enabler does not specify any resource_types to scan.",
			Remediation: "Set resource_types to include [\"ECR\", \"EC2\", \"LAMBDA\"] to enable vulnerability scanning.",
			DocURL:      r.Metadata().DocURL,
		}}
	}

	_ = resourceTypes
	return nil
}
