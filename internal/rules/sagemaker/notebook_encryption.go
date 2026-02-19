package sagemaker

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&NotebookEncryptionRule{})
}

type NotebookEncryptionRule struct{}

func (r *NotebookEncryptionRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "SM-001",
		Name:          "SageMaker Notebook Instance Should Have Encryption Enabled",
		Description:   "SageMaker notebook instance should have KMS encryption configured for data at rest.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_sagemaker_notebook_instance"},
		DocURL:        "https://docs.aws.amazon.com/sagemaker/latest/dg/encryption-at-rest.html",
	}
}

func (r *NotebookEncryptionRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	kmsKeyID, exists := resource.GetStringAttr("kms_key_id")
	if !exists || kmsKeyID == "" {
		findings = append(findings, model.Finding{
			RuleID:      r.Metadata().ID,
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityHigh,
			Pillar:      model.PillarSecurity,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "SageMaker notebook instance does not have KMS encryption configured",
			Remediation: "Set kms_key_id to a valid KMS key ARN to enable encryption at rest",
			DocURL:      "https://docs.aws.amazon.com/sagemaker/latest/dg/encryption-at-rest.html",
		})
	}

	return findings
}
