package elb

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&AccessLogsRule{})
}

type AccessLogsRule struct{}

func (r *AccessLogsRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "ELB-002",
		Name:          "Load Balancer Access Logs",
		Description:   "Load Balancers should have access logging enabled",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarOperationalExcellence,
		ResourceTypes: []string{"aws_lb"},
		DocURL:        "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html",
	}
}

func (r *AccessLogsRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	if !resource.HasBlock("access_logs") {
		findings = append(findings, model.Finding{
			RuleID:      "ELB-002",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarOperationalExcellence,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "Load balancer does not have access logging configured",
			Remediation: "Add access_logs block with enabled set to true",
		})
		return findings
	}

	blocks := resource.GetBlocks("access_logs")
	if len(blocks) > 0 {
		logsBlock := blocks[0]
		enabled, exists := logsBlock.GetBoolAttr("enabled")
		if !exists || !enabled {
			findings = append(findings, model.Finding{
				RuleID:      "ELB-002",
				RuleName:    r.Metadata().Name,
				Severity:    model.SeverityMedium,
				Pillar:      model.PillarOperationalExcellence,
				Resource:    resource.Address(),
				File:        resource.File,
				Line:        resource.Line,
				Description: "Load balancer access logging is not enabled",
				Remediation: "Set enabled to true in access_logs block",
			})
		}
	}

	return findings
}
