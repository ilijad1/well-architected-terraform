package sustainability

import (
	"strings"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// GravitonDocDBRule checks if DocumentDB instances use Graviton-based instance classes.
type GravitonDocDBRule struct{}

func init() {
	engine.Register(&GravitonDocDBRule{})
}

func (r *GravitonDocDBRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "SUS-017",
		Name:          "DocumentDB Not Using Graviton",
		Description:   "DocumentDB cluster instances should use Graviton-based instance classes (e.g., db.t4g, db.r6g) for better energy efficiency and price-performance.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarSustainability,
		ResourceTypes: []string{"aws_docdb_cluster_instance"},
	}
}

func (r *GravitonDocDBRule) Evaluate(resource model.TerraformResource) []model.Finding {
	instanceClass, ok := resource.GetStringAttr("instance_class")
	if !ok || instanceClass == "" {
		return nil
	}

	if isDocDBGraviton(instanceClass) {
		return nil
	}

	return []model.Finding{{
		RuleID:      "SUS-017",
		RuleName:    "DocumentDB Not Using Graviton",
		Severity:    model.SeverityLow,
		Pillar:      model.PillarSustainability,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "DocumentDB instance class " + instanceClass + " is not a Graviton type. Graviton instances offer better price-performance and lower energy consumption.",
		Remediation: "Migrate to a Graviton-based DocumentDB instance class such as db.t4g.medium, db.r6g.large, or db.r7g.large.",
	}}
}

// isDocDBGraviton checks if a DocumentDB instance class uses Graviton.
// DocumentDB instance classes use the format "db.t4g.medium" — split by "." and check index [1].
func isDocDBGraviton(instanceClass string) bool {
	parts := strings.Split(instanceClass, ".")
	if len(parts) < 3 {
		return false
	}
	// parts[0] = "db", parts[1] = family (e.g., "t4g", "r6g"), parts[2] = size
	family := parts[1]
	return strings.HasSuffix(family, "g") || strings.HasSuffix(family, "gd")
}
