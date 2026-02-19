package ecr

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&LifecyclePolicy{})
}

type LifecyclePolicy struct{}

func (r *LifecyclePolicy) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "ECR-005", Name: "ECR Lifecycle Policy", Description: "ECR repositories should have a lifecycle policy to manage image retention.", Severity: model.SeverityLow, Pillar: model.PillarCostOptimization, ResourceTypes: []string{"aws_ecr_lifecycle_policy"}}
}

func (r *LifecyclePolicy) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetStringAttr("policy"); ok && v != "" {
		return nil
	}
	return []model.Finding{{RuleID: "ECR-005", RuleName: r.Metadata().Name, Severity: model.SeverityLow, Pillar: model.PillarCostOptimization, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "ECR lifecycle policy does not have a policy configured.", Remediation: "Set policy to a valid lifecycle policy JSON."}}
}
