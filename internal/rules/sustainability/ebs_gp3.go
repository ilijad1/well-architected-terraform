package sustainability

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// EBSGP3Rule checks if EBS volumes use gp3 instead of older gp2.
type EBSGP3Rule struct{}

func init() {
	engine.Register(&EBSGP3Rule{})
}

func (r *EBSGP3Rule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "SUS-007",
		Name:          "EBS Volume Using gp2",
		Description:   "EBS volumes should use gp3 instead of gp2 for better efficiency and cost savings.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarSustainability,
		ResourceTypes: []string{"aws_ebs_volume"},
	}
}

func (r *EBSGP3Rule) Evaluate(resource model.TerraformResource) []model.Finding {
	volumeType, ok := resource.GetStringAttr("type")
	if !ok || volumeType != "gp2" {
		return nil
	}

	return []model.Finding{{
		RuleID:      "SUS-007",
		RuleName:    "EBS Volume Using gp2",
		Severity:    model.SeverityLow,
		Pillar:      model.PillarSustainability,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "This EBS volume uses gp2, which is older and less cost-efficient than gp3. gp3 provides the same baseline performance at a lower price.",
		Remediation: "Change the volume type from gp2 to gp3. gp3 provides 3,000 IOPS and 125 MiB/s throughput at no additional cost.",
	}}
}
