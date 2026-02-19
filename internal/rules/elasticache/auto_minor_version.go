package elasticache

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&AutoMinorVersionRule{})
}

type AutoMinorVersionRule struct{}

func (r *AutoMinorVersionRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "EC-005",
		Name:          "ElastiCache auto minor version upgrade",
		Description:   "ElastiCache replication groups should have auto minor version upgrade enabled.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarOperationalExcellence,
		ResourceTypes: []string{"aws_elasticache_replication_group"},
	}
}

func (r *AutoMinorVersionRule) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetBoolAttr("auto_minor_version_upgrade"); ok && !v {
		return []model.Finding{{
			RuleID:      "EC-005",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityLow,
			Pillar:      model.PillarOperationalExcellence,
			Resource:    resource.FullAddress,
			File:        resource.File,
			Line:        resource.Line,
			Description: "ElastiCache replication group does not have auto minor version upgrade enabled",
			Remediation: "Set auto_minor_version_upgrade to true or remove the attribute (defaults to true)",
		}}
	}
	return nil
}
