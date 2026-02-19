package lambda

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&PermissionWildcard{})
}

// PermissionWildcard checks that Lambda permissions do not use wildcard principals.
type PermissionWildcard struct{}

func (r *PermissionWildcard) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "LAM-007",
		Name:          "Lambda Permission No Wildcard Principal",
		Description:   "Lambda function permissions should not use a wildcard (*) as the principal, which makes the function publicly invocable.",
		Severity:      model.SeverityCritical,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_lambda_permission"},
		DocURL:        "https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html",
	}
}

func (r *PermissionWildcard) Evaluate(resource model.TerraformResource) []model.Finding {
	principal, ok := resource.GetStringAttr("principal")
	if ok && principal == "*" {
		return []model.Finding{{
			RuleID:      "LAM-007",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityCritical,
			Pillar:      model.PillarSecurity,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "Lambda permission uses a wildcard principal (*), making the function publicly invocable by anyone.",
			Remediation: "Replace the wildcard principal with a specific AWS service or account ARN.",
			DocURL:      r.Metadata().DocURL,
		}}
	}
	return nil
}
