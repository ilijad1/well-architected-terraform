package ecr

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&Encryption{})
}

type Encryption struct{}

func (r *Encryption) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "ECR-003",
		Name:          "ECR KMS Encryption",
		Description:   "ECR repositories should use KMS encryption.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_ecr_repository"},
	}
}

func (r *Encryption) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, block := range resource.GetBlocks("encryption_configuration") {
		encType, ok := block.GetStringAttr("encryption_type")
		if ok && encType == "KMS" {
			return nil
		}
	}

	return []model.Finding{{
		RuleID:      "ECR-003",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "ECR repository is not encrypted with KMS.",
		Remediation: "Add encryption_configuration block with encryption_type = \"KMS\".",
	}}
}
