package iam

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&UserGroupMembership{})
}

// UserGroupMembership checks that IAM users are managed via groups, not standalone.
// AWS best practice is to assign permissions via groups, not directly to users.
// This rule flags aws_iam_user resources, since standalone users without group
// membership are harder to manage at scale. Users should be added to groups
// via aws_iam_user_group_membership.
type UserGroupMembership struct{}

func (r *UserGroupMembership) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "IAM-007",
		Name:          "IAM User Group Membership",
		Description:   "IAM users should be managed through groups rather than having permissions assigned directly. Use aws_iam_user_group_membership to assign users to groups.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_iam_user"},
		DocURL:        "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#use-groups-for-permissions",
	}
}

func (r *UserGroupMembership) Evaluate(resource model.TerraformResource) []model.Finding {
	// Flag every aws_iam_user — the check is that group membership should be
	// managed separately via aws_iam_user_group_membership.
	// Cross-resource correlation (checking if a corresponding membership exists)
	// is not possible in single-resource rule evaluation, so we flag the
	// existence of standalone IAM users as a reminder to verify group membership.
	return []model.Finding{{
		RuleID:      "IAM-007",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "IAM user is defined without verified group membership. IAM users should be managed through groups.",
		Remediation: "Add the user to appropriate IAM groups using aws_iam_user_group_membership and avoid attaching policies directly to users.",
		DocURL:      r.Metadata().DocURL,
	}}
}
