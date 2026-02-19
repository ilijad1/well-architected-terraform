// Package iam contains Well-Architected rules for AWS IAM resources.
package iam

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// AccessKeyRule flags the creation of IAM access keys — humans should use SSO.
type AccessKeyRule struct{}

func init() {
	engine.Register(&AccessKeyRule{})
}

func (r *AccessKeyRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "IAM-008",
		Name:          "IAM Access Key Exists",
		Description:   "IAM access keys for users should be avoided; use IAM Identity Center (SSO) or IAM roles instead.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_iam_access_key"},
		ComplianceFrameworks: map[string][]string{
			"CIS": {"1.4"},
		},
	}
}

func (r *AccessKeyRule) Evaluate(resource model.TerraformResource) []model.Finding {
	return []model.Finding{{
		RuleID:      "IAM-008",
		RuleName:    "IAM Access Key Exists",
		Severity:    model.SeverityHigh,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "An IAM access key is being created. Long-lived credentials are a security risk; use IAM Identity Center (SSO) or IAM roles for human users.",
		Remediation: "Remove the aws_iam_access_key resource and configure IAM Identity Center for human access. Use IAM roles with temporary credentials for programmatic access.",
	}}
}
