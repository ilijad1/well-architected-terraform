package sustainability

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// OpenSearchUltraWarmRule checks if OpenSearch domains have UltraWarm enabled for cost-efficient warm storage.
type OpenSearchUltraWarmRule struct{}

func init() {
	engine.Register(&OpenSearchUltraWarmRule{})
}

func (r *OpenSearchUltraWarmRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "SUS-015",
		Name:          "OpenSearch Missing UltraWarm",
		Description:   "OpenSearch domains should enable UltraWarm storage to tier infrequently accessed data to lower-cost storage, reducing energy usage and cost.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarSustainability,
		ResourceTypes: []string{"aws_opensearch_domain"},
	}
}

func (r *OpenSearchUltraWarmRule) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, block := range resource.GetBlocks("cluster_config") {
		enabled, ok := block.GetBoolAttr("warm_enabled")
		if ok && enabled {
			return nil
		}
	}

	return []model.Finding{{
		RuleID:      "SUS-015",
		RuleName:    "OpenSearch Missing UltraWarm",
		Severity:    model.SeverityLow,
		Pillar:      model.PillarSustainability,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "This OpenSearch domain does not have UltraWarm storage enabled. UltraWarm provides cost-efficient warm storage for infrequently accessed data.",
		Remediation: "Enable UltraWarm by setting warm_enabled = true in the cluster_config block and specifying warm_count and warm_type.",
	}}
}
