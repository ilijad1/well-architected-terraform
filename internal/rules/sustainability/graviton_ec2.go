package sustainability

import (
	"strings"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// GravitonEC2Rule checks if EC2 instances use Graviton (ARM) instance types.
type GravitonEC2Rule struct{}

func init() {
	engine.Register(&GravitonEC2Rule{})
}

func (r *GravitonEC2Rule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "SUS-001",
		Name:          "EC2 Instance Not Using Graviton",
		Description:   "EC2 instances should use Graviton (ARM) instance types for better energy efficiency and cost performance.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarSustainability,
		ResourceTypes: []string{"aws_instance", "aws_launch_template"},
	}
}

func (r *GravitonEC2Rule) Evaluate(resource model.TerraformResource) []model.Finding {
	instanceType, ok := resource.GetStringAttr("instance_type")
	if !ok || instanceType == "" {
		return nil
	}

	if isGravitonInstanceType(instanceType) {
		return nil
	}

	return []model.Finding{{
		RuleID:      "SUS-001",
		RuleName:    "EC2 Instance Not Using Graviton",
		Severity:    model.SeverityLow,
		Pillar:      model.PillarSustainability,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "Instance type " + instanceType + " is not a Graviton (ARM) instance. Graviton instances offer better price-performance and lower energy consumption.",
		Remediation: "Consider migrating to a Graviton instance type (e.g., m7g, c7g, r7g, t4g). Verify your application supports ARM64 architecture.",
	}}
}

// isGravitonInstanceType checks if an instance type uses a Graviton processor.
// Graviton types contain 'g' in the generation suffix: m7g, c7g, r7g, t4g, etc.
func isGravitonInstanceType(instanceType string) bool {
	parts := strings.Split(instanceType, ".")
	if len(parts) < 2 {
		return false
	}
	family := parts[0]
	// Graviton families end with 'g' or 'gd'
	return strings.HasSuffix(family, "g") || strings.HasSuffix(family, "gd")
}
