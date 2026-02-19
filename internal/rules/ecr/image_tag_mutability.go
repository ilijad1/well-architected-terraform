package ecr

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&ImageTagMutability{})
}

type ImageTagMutability struct{}

func (r *ImageTagMutability) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "ECR-002",
		Name:          "ECR Image Tag Immutability",
		Description:   "ECR repositories should have immutable image tags to prevent tag overwriting.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_ecr_repository"},
	}
}

func (r *ImageTagMutability) Evaluate(resource model.TerraformResource) []model.Finding {
	mutability, ok := resource.GetStringAttr("image_tag_mutability")
	if ok && mutability == "IMMUTABLE" {
		return nil
	}

	return []model.Finding{{
		RuleID:      "ECR-002",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "ECR repository does not have immutable image tags configured.",
		Remediation: "Set image_tag_mutability = \"IMMUTABLE\" to prevent image tag overwriting.",
	}}
}
