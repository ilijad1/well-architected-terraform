package secretsmanager

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&Rotation{})
}

type Rotation struct{}

func (r *Rotation) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "SEC-002",
		Name:          "Secrets Manager Rotation Configured",
		Description:   "Secrets Manager secrets should have rotation configured.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_secretsmanager_secret_rotation"},
	}
}

func (r *Rotation) Evaluate(resource model.TerraformResource) []model.Finding {
	lambdaArn, hasLambda := resource.GetStringAttr("rotation_lambda_arn")
	hasRules := resource.HasBlock("rotation_rules")

	if hasLambda && lambdaArn != "" && hasRules {
		return nil
	}

	return []model.Finding{{
		RuleID:      "SEC-002",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "Secrets Manager secret rotation is not fully configured.",
		Remediation: "Set rotation_lambda_arn and add a rotation_rules block.",
	}}
}
