package ec2

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&InstanceProfile{})
}

// InstanceProfile checks that EC2 instances have an IAM instance profile attached.
type InstanceProfile struct{}

func (r *InstanceProfile) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "EC2-009",
		Name:          "EC2 Instance Profile Attached",
		Description:   "EC2 instances should have an IAM instance profile attached for role-based access instead of storing credentials.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_instance"},
		DocURL:        "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2_instance-profiles.html",
	}
}

func (r *InstanceProfile) Evaluate(resource model.TerraformResource) []model.Finding {
	profile, ok := resource.GetStringAttr("iam_instance_profile")
	if ok && profile != "" {
		return nil
	}
	return []model.Finding{{
		RuleID:      "EC2-009",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "EC2 instance does not have an IAM instance profile attached.",
		Remediation: "Set iam_instance_profile to an IAM instance profile to enable role-based access without storing credentials.",
		DocURL:      r.Metadata().DocURL,
	}}
}
