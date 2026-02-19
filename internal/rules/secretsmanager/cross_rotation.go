package secretsmanager

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// CrossRotationRule checks that every Secrets Manager secret has a corresponding
// aws_secretsmanager_secret_rotation resource in the plan.
type CrossRotationRule struct{}

func init() {
	engine.RegisterCross(&CrossRotationRule{})
}

func (r *CrossRotationRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "SEC-004",
		Name:          "Secrets Manager Secret Missing Rotation",
		Description:   "Every Secrets Manager secret should have an aws_secretsmanager_secret_rotation resource to ensure credentials are automatically rotated.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_secretsmanager_secret", "aws_secretsmanager_secret_rotation"},
	}
}

func (r *CrossRotationRule) EvaluateAll(resources []model.TerraformResource) []model.Finding {
	// Index rotation resources by their secret_id attribute (or resource name)
	rotatedSecrets := make(map[string]bool)
	for _, res := range resources {
		if res.Type == "aws_secretsmanager_secret_rotation" {
			secretID, ok := res.GetStringAttr("secret_id")
			if ok && secretID != "" {
				rotatedSecrets[secretID] = true
			}
			rotatedSecrets[res.Name] = true
		}
	}

	var findings []model.Finding
	for _, res := range resources {
		if res.Type != "aws_secretsmanager_secret" {
			continue
		}

		secretName, _ := res.GetStringAttr("name")

		if !rotatedSecrets[secretName] && !rotatedSecrets[res.Address()] && !rotatedSecrets[res.Name] {
			findings = append(findings, model.Finding{
				RuleID:      "SEC-004",
				RuleName:    "Secrets Manager Secret Missing Rotation",
				Severity:    model.SeverityHigh,
				Pillar:      model.PillarSecurity,
				Resource:    res.Address(),
				File:        res.File,
				Line:        res.Line,
				Description: "This Secrets Manager secret has no aws_secretsmanager_secret_rotation resource. Without automatic rotation, long-lived credentials increase the risk of compromise.",
				Remediation: "Add an aws_secretsmanager_secret_rotation resource referencing this secret via secret_id and configure a rotation Lambda function.",
			})
		}
	}

	return findings
}
