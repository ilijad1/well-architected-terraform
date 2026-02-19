package ec2

import (
	"fmt"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&ASGMinSize{})
}

// ASGMinSize checks that Auto Scaling Groups have min_size >= 2 for high availability.
type ASGMinSize struct{}

func (r *ASGMinSize) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "EC2-003",
		Name:          "Auto Scaling Group Minimum Size",
		Description:   "Auto Scaling Groups should have min_size >= 2 for high availability.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarReliability,
		ResourceTypes: []string{"aws_autoscaling_group"},
	}
}

func (r *ASGMinSize) Evaluate(resource model.TerraformResource) []model.Finding {
	minSize, ok := resource.GetNumberAttr("min_size")
	if ok && minSize >= 2 {
		return nil
	}

	return []model.Finding{{
		RuleID:      "EC2-003",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarReliability,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: fmt.Sprintf("Auto Scaling Group has min_size of %.0f, which does not provide high availability.", minSize),
		Remediation: "Set min_size to at least 2 to ensure high availability across failures.",
	}}
}
