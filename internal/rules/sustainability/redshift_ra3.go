package sustainability

import (
	"strings"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// RedshiftRA3Rule checks if Redshift clusters use RA3 node types for managed storage.
type RedshiftRA3Rule struct{}

func init() {
	engine.Register(&RedshiftRA3Rule{})
}

func (r *RedshiftRA3Rule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "SUS-014",
		Name:          "Redshift Not Using RA3 Nodes",
		Description:   "Redshift clusters should use RA3 node types which separate compute and storage, allowing independent scaling and reducing resource waste.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarSustainability,
		ResourceTypes: []string{"aws_redshift_cluster"},
	}
}

func (r *RedshiftRA3Rule) Evaluate(resource model.TerraformResource) []model.Finding {
	nodeType, ok := resource.GetStringAttr("node_type")
	if !ok || nodeType == "" {
		return nil
	}

	if strings.HasPrefix(nodeType, "ra3.") {
		return nil
	}

	return []model.Finding{{
		RuleID:      "SUS-014",
		RuleName:    "Redshift Not Using RA3 Nodes",
		Severity:    model.SeverityLow,
		Pillar:      model.PillarSustainability,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "Redshift node type " + nodeType + " is not an RA3 type. RA3 nodes use managed storage that scales independently of compute, preventing over-provisioning.",
		Remediation: "Migrate to an RA3 node type (ra3.xlplus, ra3.4xlarge, or ra3.16xlarge) to decouple compute and storage scaling.",
	}}
}
