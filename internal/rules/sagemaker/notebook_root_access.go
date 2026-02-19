package sagemaker

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&NotebookRootAccessRule{})
}

type NotebookRootAccessRule struct{}

func (r *NotebookRootAccessRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "SM-003",
		Name:          "SageMaker Notebook Instance Should Have Root Access Disabled",
		Description:   "SageMaker notebook instance should have root access disabled to follow the principle of least privilege.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_sagemaker_notebook_instance"},
		DocURL:        "https://docs.aws.amazon.com/sagemaker/latest/dg/nbi-root-access.html",
	}
}

func (r *NotebookRootAccessRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	rootAccess, exists := resource.GetStringAttr("root_access")
	if !exists || rootAccess != "Disabled" {
		findings = append(findings, model.Finding{
			RuleID:      r.Metadata().ID,
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarSecurity,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "SageMaker notebook instance has root access enabled, which violates the principle of least privilege",
			Remediation: "Set root_access = \"Disabled\" to prevent users from gaining root access to the notebook instance",
			DocURL:      "https://docs.aws.amazon.com/sagemaker/latest/dg/nbi-root-access.html",
		})
	}

	return findings
}
