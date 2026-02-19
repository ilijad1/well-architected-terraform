package sustainability

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// LambdaARMRule checks if Lambda functions use ARM64 architecture.
type LambdaARMRule struct{}

func init() {
	engine.Register(&LambdaARMRule{})
}

func (r *LambdaARMRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "SUS-005",
		Name:          "Lambda Not Using ARM64 Architecture",
		Description:   "Lambda functions should use arm64 architecture (Graviton2) for better price-performance and energy efficiency.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarSustainability,
		ResourceTypes: []string{"aws_lambda_function"},
	}
}

func (r *LambdaARMRule) Evaluate(resource model.TerraformResource) []model.Finding {
	// architectures is a list attribute
	archAttr, ok := resource.Attributes["architectures"]
	if ok {
		if archs, ok := archAttr.([]interface{}); ok {
			for _, a := range archs {
				if s, ok := a.(string); ok && s == "arm64" {
					return nil
				}
			}
		}
	}

	return []model.Finding{{
		RuleID:      "SUS-005",
		RuleName:    "Lambda Not Using ARM64 Architecture",
		Severity:    model.SeverityLow,
		Pillar:      model.PillarSustainability,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "This Lambda function does not use arm64 architecture. Graviton2-based Lambda functions offer up to 34% better price-performance and lower energy consumption.",
		Remediation: "Set architectures = [\"arm64\"] on the Lambda function. Ensure your runtime and dependencies support ARM64.",
	}}
}
