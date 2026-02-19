package kms

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&TagsRule{})
}

type TagsRule struct{}

func (r *TagsRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "KMS-003",
		Name:          "KMS Key Should Have Tags",
		Description:   "KMS key should have tags for better resource organization and cost allocation.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarCostOptimization,
		ResourceTypes: []string{"aws_kms_key"},
		DocURL:        "https://docs.aws.amazon.com/kms/latest/developerguide/tagging-keys.html",
	}
}

func (r *TagsRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	// Check if tags block exists
	if !resource.HasBlock("tags") {
		findings = append(findings, model.Finding{
			RuleID:      r.Metadata().ID,
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityLow,
			Pillar:      model.PillarCostOptimization,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "KMS key does not have any tags, which makes cost tracking and resource management difficult",
			Remediation: "Add tags to the KMS key for better resource organization and cost allocation",
			DocURL:      "https://docs.aws.amazon.com/kms/latest/developerguide/tagging-keys.html",
		})
	}

	return findings
}
