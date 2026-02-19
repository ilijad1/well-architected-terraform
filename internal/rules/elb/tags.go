package elb

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&TagsRule{})
}

type TagsRule struct{}

func (r *TagsRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "ELB-005",
		Name:          "Load Balancer Tags",
		Description:   "Load Balancers should have tags for cost allocation and resource management",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarCostOptimization,
		ResourceTypes: []string{"aws_lb"},
		DocURL:        "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-tags.html",
	}
}

func (r *TagsRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	if !resource.HasBlock("tags") {
		findings = append(findings, model.Finding{
			RuleID:      "ELB-005",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityLow,
			Pillar:      model.PillarCostOptimization,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "Load balancer does not have tags configured",
			Remediation: "Add tags block to enable cost allocation and resource management",
		})
	}

	return findings
}
