package sagemaker

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&NotebookDirectInternetRule{})
}

type NotebookDirectInternetRule struct{}

func (r *NotebookDirectInternetRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "SM-002",
		Name:          "SageMaker Notebook Instance Should Not Have Direct Internet Access",
		Description:   "SageMaker notebook instance should have direct internet access disabled to reduce attack surface.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_sagemaker_notebook_instance"},
		DocURL:        "https://docs.aws.amazon.com/sagemaker/latest/dg/appendix-notebook-and-internet-access.html",
	}
}

func (r *NotebookDirectInternetRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	directInternetAccess, exists := resource.GetStringAttr("direct_internet_access")
	if !exists || directInternetAccess != "Disabled" {
		findings = append(findings, model.Finding{
			RuleID:      r.Metadata().ID,
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityHigh,
			Pillar:      model.PillarSecurity,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "SageMaker notebook instance has direct internet access enabled, which increases the attack surface",
			Remediation: "Set direct_internet_access = \"Disabled\" and use VPC endpoints for AWS service access",
			DocURL:      "https://docs.aws.amazon.com/sagemaker/latest/dg/appendix-notebook-and-internet-access.html",
		})
	}

	return findings
}
