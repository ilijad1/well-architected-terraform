package ecr

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&ScanOnPush{})
}

type ScanOnPush struct{}

func (r *ScanOnPush) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "ECR-001",
		Name:          "ECR Image Scan on Push",
		Description:   "ECR repositories should have image scanning on push enabled.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_ecr_repository"},
	}
}

func (r *ScanOnPush) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, block := range resource.GetBlocks("image_scanning_configuration") {
		enabled, ok := block.GetBoolAttr("scan_on_push")
		if ok && enabled {
			return nil
		}
	}

	return []model.Finding{{
		RuleID:      "ECR-001",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityHigh,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "ECR repository does not have image scanning on push enabled.",
		Remediation: "Add image_scanning_configuration block with scan_on_push = true.",
	}}
}
