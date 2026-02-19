package lambda

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&EnvEncryptionRule{})
}

type EnvEncryptionRule struct{}

func (r *EnvEncryptionRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "LAM-003",
		Name:          "Lambda Environment Variables Encrypted with CMK",
		Description:   "Ensures Lambda functions encrypt environment variables using a customer-managed KMS key",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_lambda_function"},
		DocURL:        "https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html#configuration-envvars-encryption",
	}
}

func (r *EnvEncryptionRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	// Check if environment block exists
	if !resource.HasBlock("environment") {
		// No environment variables, rule doesn't apply
		return nil
	}

	// Check if environment block has variables
	envBlocks := resource.GetBlocks("environment")
	hasVariables := false

	for _, block := range envBlocks {
		if variables, ok := block.Attributes["variables"].(map[string]interface{}); ok && len(variables) > 0 {
			hasVariables = true
			break
		}
	}

	if !hasVariables {
		// No variables defined, rule doesn't apply
		return nil
	}

	// If environment variables exist, check for CMK encryption
	kmsKeyArn, ok := resource.GetStringAttr("kms_key_arn")
	if !ok || kmsKeyArn == "" {
		findings = append(findings, model.Finding{
			RuleID:      "LAM-003",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarSecurity,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "Lambda function has environment variables but they are not encrypted with a customer-managed KMS key",
			Remediation: "Set the kms_key_arn attribute to a customer-managed KMS key ARN to encrypt environment variables at rest",
			DocURL:      r.Metadata().DocURL,
		})
	}

	return findings
}
