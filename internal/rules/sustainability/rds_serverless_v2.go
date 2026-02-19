package sustainability

import (
	"strings"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// RDSServerlessV2Rule checks if Aurora clusters have serverless v2 scaling configured.
type RDSServerlessV2Rule struct{}

func init() {
	engine.Register(&RDSServerlessV2Rule{})
}

func (r *RDSServerlessV2Rule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "SUS-012",
		Name:          "Aurora Missing Serverless v2 Scaling",
		Description:   "Aurora clusters should use serverless v2 scaling configuration to dynamically scale capacity and reduce resource waste during low-traffic periods.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarSustainability,
		ResourceTypes: []string{"aws_rds_cluster"},
	}
}

func (r *RDSServerlessV2Rule) Evaluate(resource model.TerraformResource) []model.Finding {
	engine, ok := resource.GetStringAttr("engine")
	if !ok || !strings.Contains(strings.ToLower(engine), "aurora") {
		// Only apply to Aurora clusters
		return nil
	}

	for _, block := range resource.GetBlocks("serverless_v2_scaling_configuration") {
		v, ok := block.Attributes["max_capacity"]
		if !ok {
			continue
		}
		switch n := v.(type) {
		case float64:
			if n > 0 {
				return nil
			}
		case int:
			if n > 0 {
				return nil
			}
		}
	}

	return []model.Finding{{
		RuleID:      "SUS-012",
		RuleName:    "Aurora Missing Serverless v2 Scaling",
		Severity:    model.SeverityLow,
		Pillar:      model.PillarSustainability,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "This Aurora cluster does not have serverless_v2_scaling_configuration configured. Serverless v2 can scale to near-zero during idle periods, reducing energy and cost.",
		Remediation: "Add a serverless_v2_scaling_configuration block with min_capacity and max_capacity values and configure Aurora Serverless v2 instances.",
	}}
}
