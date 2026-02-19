package sustainability

import (
	"strings"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// GravitonRDSRule checks if RDS instances use Graviton instance classes.
type GravitonRDSRule struct{}

func init() {
	engine.Register(&GravitonRDSRule{})
}

func (r *GravitonRDSRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "SUS-002",
		Name:          "RDS Instance Not Using Graviton",
		Description:   "RDS instances should use Graviton-based instance classes (db.m7g, db.r7g, db.t4g) for better energy efficiency.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarSustainability,
		ResourceTypes: []string{"aws_db_instance"},
	}
}

func (r *GravitonRDSRule) Evaluate(resource model.TerraformResource) []model.Finding {
	instanceClass, ok := resource.GetStringAttr("instance_class")
	if !ok || instanceClass == "" {
		return nil
	}

	// db.m7g.large, db.r7g.xlarge, db.t4g.medium — Graviton
	parts := strings.Split(instanceClass, ".")
	if len(parts) >= 2 {
		family := parts[1]
		if strings.HasSuffix(family, "g") || strings.HasSuffix(family, "gd") {
			return nil
		}
	}

	return []model.Finding{{
		RuleID:      "SUS-002",
		RuleName:    "RDS Instance Not Using Graviton",
		Severity:    model.SeverityLow,
		Pillar:      model.PillarSustainability,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "RDS instance class " + instanceClass + " is not Graviton-based. Graviton instances deliver better price-performance with lower energy consumption.",
		Remediation: "Consider migrating to a Graviton instance class (e.g., db.m7g, db.r7g, db.t4g). Verify database engine compatibility with Graviton.",
	}}
}
