package elb

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&DropInvalidHeadersRule{})
}

type DropInvalidHeadersRule struct{}

func (r *DropInvalidHeadersRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "ELB-001",
		Name:          "Load Balancer Drop Invalid Headers",
		Description:   "Application Load Balancers should drop invalid HTTP headers",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_lb"},
		DocURL:        "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#invalid-header-fields",
	}
}

func (r *DropInvalidHeadersRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	dropHeaders, exists := resource.GetBoolAttr("drop_invalid_header_fields")
	if !exists || !dropHeaders {
		findings = append(findings, model.Finding{
			RuleID:      "ELB-001",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarSecurity,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "Load balancer does not drop invalid HTTP headers",
			Remediation: "Set drop_invalid_header_fields to true to improve security",
		})
	}

	return findings
}
