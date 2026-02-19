package sustainability

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// MSKgp3Rule checks if MSK clusters use gp3 EBS storage for better cost efficiency.
type MSKgp3Rule struct{}

func init() {
	engine.Register(&MSKgp3Rule{})
}

func (r *MSKgp3Rule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "SUS-016",
		Name:          "MSK Broker Not Using gp3 Storage",
		Description:   "MSK clusters should use gp3 EBS storage for brokers, which offers better performance per GB and lower cost than gp2.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarSustainability,
		ResourceTypes: []string{"aws_msk_cluster"},
	}
}

func (r *MSKgp3Rule) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, bng := range resource.GetBlocks("broker_node_group_info") {
		for _, si := range bng.Blocks["storage_info"] {
			for _, ebs := range si.Blocks["ebs_storage_info"] {
				vt, ok := ebs.GetStringAttr("volume_type")
				if ok && vt == "gp3" {
					return nil
				}
			}
		}
	}

	return []model.Finding{{
		RuleID:      "SUS-016",
		RuleName:    "MSK Broker Not Using gp3 Storage",
		Severity:    model.SeverityLow,
		Pillar:      model.PillarSustainability,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "This MSK cluster's broker nodes are not using gp3 EBS storage. gp3 provides 20% lower cost and better performance than gp2.",
		Remediation: "Set volume_type = \"gp3\" in the broker_node_group_info > storage_info > ebs_storage_info block.",
	}}
}
