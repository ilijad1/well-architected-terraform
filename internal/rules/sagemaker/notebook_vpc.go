package sagemaker

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&NotebookVPC{})
}

type NotebookVPC struct{}

func (r *NotebookVPC) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "SM-005",
		Name:          "SageMaker Notebook Instance VPC",
		Description:   "SageMaker notebook instances should be deployed in a VPC.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_sagemaker_notebook_instance"},
	}
}

func (r *NotebookVPC) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetStringAttr("subnet_id"); ok && v != "" {
		return nil
	}
	return []model.Finding{{
		RuleID:      "SM-005",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "SageMaker notebook instance is not deployed in a VPC",
		Remediation: "Set subnet_id to deploy the notebook instance in a VPC",
	}}
}
